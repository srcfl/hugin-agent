// Package server is the thin HTTP surface of hugin-agent: five
// endpoints that map directly onto the protocol the Hugin web app
// (https://hugin.sourceful-labs.net) speaks. No state, no DB, no AI —
// the handlers just call into scanner/modbus/luarunner and JSON-marshal
// the result.
package server

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/srcfl/hugin-agent/internal/diagnostic"
	"github.com/srcfl/hugin-agent/internal/luarunner"
	"github.com/srcfl/hugin-agent/internal/modbus"
	"github.com/srcfl/hugin-agent/internal/scanner"
	lua "github.com/yuin/gopher-lua"
)

// Config drives the HTTP server.
type Config struct {
	Version string
	Token   string // pairing token; empty disables auth (dev only)
}

// New builds an http.Handler with all five protocol endpoints wired.
func New(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", handleInfo(cfg.Version))
	mux.HandleFunc("GET /v1/health", handleHealth)
	mux.HandleFunc("POST /v1/scan", auth(cfg.Token, handleScan))
	mux.HandleFunc("POST /v1/probe", auth(cfg.Token, handleProbe))
	mux.HandleFunc("POST /v1/run-lua", auth(cfg.Token, handleRunLua))
	return cors(logger(mux))
}

// auth wraps a handler in Bearer-token validation. constant-time compare.
func auth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(got) <= len(prefix) || got[:len(prefix)] != prefix {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		if subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(token)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	}
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wide-open: this is a localhost agent; the user paired it
		// from a browser. Any origin is allowed; auth is per-request.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "3600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(t0))
	})
}

// --- handlers ---

func handleInfo(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"name":             "hugin-agent",
			"version":          version,
			"protocol_version": 1,
			"capabilities":     []string{"scan", "probe", "run-lua"},
		})
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"ts":     time.Now().UTC().Format(time.RFC3339),
	})
}

type scanRequest struct {
	CIDR       string `json:"cidr"`
	Ports      []int  `json:"ports"`
	DeepProbe  bool   `json:"deep_probe"`
}

type scanDevice struct {
	IP         string         `json:"ip"`
	MAC        string         `json:"mac,omitempty"`
	VendorOUI  string         `json:"vendor_oui,omitempty"`
	OpenPorts  []int          `json:"open_ports"`
	Modbus     map[string]any `json:"modbus,omitempty"`
	HTTPBanner string         `json:"http_banner,omitempty"`
}

type scanResponse struct {
	Devices []scanDevice `json:"devices"`
	Errors  []string     `json:"errors"`
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	cidr := req.CIDR
	if cidr == "" {
		cidr = scanner.LocalCIDR()
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = []int{502, 80, 1883}
	}

	resp := scanResponse{Devices: []scanDevice{}, Errors: []string{}}

	hosts, err := scanner.ScanSubnetMultiPort(cidr, ports, 1500*time.Millisecond)
	if err != nil {
		resp.Errors = append(resp.Errors, "tcp_sweep: "+err.Error())
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// scanner.ScanSubnetMultiPort returns one Host per (ip, open-port) pair.
	// Group by IP so the response carries a single device with all its ports.
	portsByIP := map[string][]int{}
	for _, h := range hosts {
		if !containsInt(portsByIP[h.IP], h.Port) {
			portsByIP[h.IP] = append(portsByIP[h.IP], h.Port)
		}
	}

	arpEntries, _ := scanner.ArpScan(cidr) // best-effort; missing ARP is fine
	macByIP := map[string]string{}
	ouiByIP := map[string]string{}
	for _, a := range arpEntries {
		macByIP[a.IP] = a.MAC
		ouiByIP[a.IP] = a.OUI
	}

	httpBanners := scanner.HTTPProbeBatch(hosts)
	bannerByIP := map[string]string{}
	for _, b := range httpBanners {
		if b.Title != "" {
			bannerByIP[b.IP] = b.Title
		} else if b.ServerHeader != "" {
			bannerByIP[b.IP] = b.ServerHeader
		}
	}

	for ip, openPorts := range portsByIP {
		dev := scanDevice{
			IP:         ip,
			MAC:        macByIP[ip],
			VendorOUI:  ouiByIP[ip],
			OpenPorts:  openPorts,
			HTTPBanner: bannerByIP[ip],
		}
		if req.DeepProbe && containsInt(openPorts, 502) {
			fc43 := diagnostic.ProbeFC43(ip, 502, []byte{1})
			if fc43.OK {
				dev.Modbus = map[string]any{
					"fc43_make":    fc43.VendorName,
					"fc43_model":   fc43.ProductName,
					"product_code": fc43.ProductCode,
					"revision":     fc43.Revision,
				}
			}
		}
		resp.Devices = append(resp.Devices, dev)
	}

	writeJSON(w, http.StatusOK, resp)
}

type registerSpec struct {
	Addr  uint16 `json:"addr"`
	Count uint16 `json:"count"`
	Kind  string `json:"kind"`
}

type probeRequest struct {
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	Modbus   struct {
		Port      int            `json:"port"`
		SlaveID   byte           `json:"slave_id"`
		Registers []registerSpec `json:"registers"`
	} `json:"modbus"`
}

type probeResultEntry struct {
	Addr   uint16  `json:"addr"`
	Value  float64 `json:"value"`
	RawHex string  `json:"raw_hex"`
}

type probeResponse struct {
	Results []probeResultEntry `json:"results"`
	Errors  []string           `json:"errors"`
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	var req probeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	if req.Protocol != "modbus" {
		writeError(w, http.StatusBadRequest, "only modbus probe supported in v0.1")
		return
	}
	port := req.Modbus.Port
	if port == 0 {
		port = 502
	}
	slaveID := req.Modbus.SlaveID
	if slaveID == 0 {
		slaveID = 1
	}

	client, err := modbus.NewTCPClientWithTimeout(req.IP, port, slaveID, 3*time.Second)
	if err != nil {
		writeError(w, http.StatusBadGateway, "connect: "+err.Error())
		return
	}
	defer client.Close()

	resp := probeResponse{Results: []probeResultEntry{}, Errors: []string{}}
	for _, reg := range req.Modbus.Registers {
		raw, err := client.ReadHoldingRegisters(reg.Addr, reg.Count)
		if err != nil {
			resp.Errors = append(resp.Errors, fmt.Sprintf("addr 0x%04X: %v", reg.Addr, err))
			continue
		}
		regs := modbus.BytesToRegisters(raw)
		dt, err := modbus.ParseDataType(reg.Kind)
		if err != nil {
			resp.Errors = append(resp.Errors, fmt.Sprintf("addr 0x%04X kind %q: %v", reg.Addr, reg.Kind, err))
			continue
		}
		endian := modbus.EndiannessFromKind(reg.Kind)
		val, err := modbus.DecodeRawValue(regs, dt, endian)
		if err != nil {
			resp.Errors = append(resp.Errors, fmt.Sprintf("addr 0x%04X decode: %v", reg.Addr, err))
			continue
		}
		resp.Results = append(resp.Results, probeResultEntry{
			Addr:   reg.Addr,
			Value:  val,
			RawHex: hex.EncodeToString(raw),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

type runLuaRequest struct {
	LuaSource  string                 `json:"lua_source"`
	Config     map[string]interface{} `json:"config"`
	Actions    []string               `json:"actions"`
	DurationMS int                    `json:"duration_ms"`
}

type emission struct {
	TS      string                 `json:"ts"`
	Channel string                 `json:"channel"`
	Data    map[string]float64     `json:"data"`
}

type runLuaResponse struct {
	OK        bool                   `json:"ok"`
	Emissions []emission             `json:"emissions"`
	Metrics   map[string]float64     `json:"metrics"`
	Logs      []string               `json:"logs"`
	Errors    []string               `json:"errors"`
}

func handleRunLua(w http.ResponseWriter, r *http.Request) {
	var req runLuaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	if req.LuaSource == "" {
		writeError(w, http.StatusBadRequest, "lua_source required")
		return
	}
	if len(req.Actions) == 0 {
		req.Actions = []string{"init", "poll"}
	}

	resp := runLuaResponse{
		Emissions: []emission{},
		Metrics:   map[string]float64{},
		Logs:      []string{},
		Errors:    []string{},
	}

	rt := luarunner.New()
	if err := rt.Init(); err != nil {
		writeError(w, http.StatusInternalServerError, "lua init: "+err.Error())
		return
	}
	defer rt.Close()

	emitFn := func(channel string, data map[string]float64) {
		copy := make(map[string]float64, len(data))
		for k, v := range data {
			copy[k] = v
		}
		resp.Emissions = append(resp.Emissions, emission{
			TS:      time.Now().UTC().Format(time.RFC3339),
			Channel: channel,
			Data:    copy,
		})
	}
	logFn := func(level, msg string) {
		resp.Logs = append(resp.Logs, "["+level+"] "+msg)
	}
	metricFn := func(name string, value float64) {
		resp.Metrics[name] = value
	}
	luarunner.RegisterStandardHostAPI(rt, emitFn, logFn, metricFn)
	luarunner.RegisterDecodeHostFuncs(rt)
	luarunner.RegisterMQTTStubs(rt) // safe stubs; real MQTT not enabled in this run

	// Wire Modbus only if config carries host/port; many drivers expect
	// host.modbus_read to exist even when polling won't reach hardware.
	host, _ := req.Config["host"].(string)
	port := 502
	if p, ok := req.Config["port"].(float64); ok && p > 0 {
		port = int(p)
	}
	slaveID := byte(1)
	if s, ok := req.Config["slave_id"].(float64); ok && s > 0 {
		slaveID = byte(s)
	}
	if host != "" {
		client, err := modbus.NewTCPClientWithTimeout(host, port, slaveID, 3*time.Second)
		if err == nil {
			bridge := luarunner.NewModbusBridge(client)
			bridge.RegisterHostFuncs(rt)
			defer client.Close()
		} else {
			resp.Errors = append(resp.Errors, "modbus connect: "+err.Error())
		}
	}
	httpBridge := luarunner.NewHTTPBridge()
	httpBridge.RegisterHostFuncs(rt)

	if err := rt.DoString(req.LuaSource); err != nil {
		resp.Errors = append(resp.Errors, "load source: "+err.Error())
		writeJSON(w, http.StatusOK, resp)
		return
	}

	for _, action := range req.Actions {
		switch action {
		case "init":
			cfgTbl := configToLuaTable(rt, req.Config)
			if _, err := rt.CallGlobal("driver_init", cfgTbl); err != nil {
				resp.Errors = append(resp.Errors, "driver_init: "+err.Error())
			}
		case "poll":
			if _, err := rt.CallGlobal("driver_poll"); err != nil {
				resp.Errors = append(resp.Errors, "driver_poll: "+err.Error())
			}
		case "cleanup":
			if _, err := rt.CallGlobal("driver_cleanup"); err != nil {
				resp.Errors = append(resp.Errors, "driver_cleanup: "+err.Error())
			}
		default:
			resp.Errors = append(resp.Errors, "unknown action: "+action)
		}
	}

	resp.OK = len(resp.Errors) == 0
	writeJSON(w, http.StatusOK, resp)
}

// --- helpers ---

func configToLuaTable(rt *luarunner.Runtime, cfg map[string]interface{}) lua.LValue {
	rt.Lock()
	defer rt.Unlock()
	L := rt.State()
	tbl := L.NewTable()
	for k, v := range cfg {
		switch x := v.(type) {
		case string:
			tbl.RawSetString(k, lua.LString(x))
		case float64:
			tbl.RawSetString(k, lua.LNumber(x))
		case bool:
			tbl.RawSetString(k, lua.LBool(x))
		}
	}
	return tbl
}

func containsInt(s []int, x int) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
