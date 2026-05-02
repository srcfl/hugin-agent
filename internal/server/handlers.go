// Package server's handlers.go exposes the agent's three operations
// (Scan / Probe / RunLua) as plain Go functions that take request
// structs and return response structs. This lets the HTTP server in
// server.go and the NATS dispatcher in cmd/hugin-agent/nats.go share
// a single implementation.
//
// Design contract:
//
//   - Functions are package-public (capitalised) and stable.
//   - Inputs are JSON-tagged structs so the same shape goes over
//     HTTP and NATS without an extra translation layer.
//   - RunLuaContext takes an EventSink callback so long-running
//     operations can stream emissions/log lines as they happen
//     instead of buffering until the end. HTTP currently buffers
//     (kept intentionally — preserves existing behaviour). NATS
//     dispatcher publishes each event as it arrives.
//
// The HTTP handlers in server.go are now thin wrappers.
package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/srcfl/hugin-agent/internal/diagnostic"
	"github.com/srcfl/hugin-agent/internal/luarunner"
	"github.com/srcfl/hugin-agent/internal/modbus"
	"github.com/srcfl/hugin-agent/internal/scanner"
	lua "github.com/yuin/gopher-lua"
)

// --- request/response types (exported, JSON-tagged) -----------------------

// ScanRequest is the body of POST /v1/scan and the agent.<id>.req.scan
// NATS subject.
type ScanRequest struct {
	CIDR      string `json:"cidr"`
	Ports     []int  `json:"ports"`
	DeepProbe bool   `json:"deep_probe"`
}

type ScanDevice struct {
	IP         string         `json:"ip"`
	MAC        string         `json:"mac,omitempty"`
	VendorOUI  string         `json:"vendor_oui,omitempty"`
	OpenPorts  []int          `json:"open_ports"`
	Modbus     map[string]any `json:"modbus,omitempty"`
	HTTPBanner string         `json:"http_banner,omitempty"`
}

type ScanResponse struct {
	Devices []ScanDevice `json:"devices"`
	Errors  []string     `json:"errors"`
}

type RegisterSpec struct {
	Addr  uint16 `json:"addr"`
	Count uint16 `json:"count"`
	Kind  string `json:"kind"`
}

// ProbeRequest body of POST /v1/probe and agent.<id>.req.probe.
type ProbeRequest struct {
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	Modbus   struct {
		Port      int            `json:"port"`
		SlaveID   byte           `json:"slave_id"`
		Registers []RegisterSpec `json:"registers"`
	} `json:"modbus"`
}

type ProbeResultEntry struct {
	Addr   uint16  `json:"addr"`
	Value  float64 `json:"value"`
	RawHex string  `json:"raw_hex"`
}

type ProbeResponse struct {
	Results []ProbeResultEntry `json:"results"`
	Errors  []string           `json:"errors"`
}

// RunLuaRequest body of POST /v1/run-lua and agent.<id>.req.run-lua.
type RunLuaRequest struct {
	LuaSource  string                 `json:"lua_source"`
	Config     map[string]interface{} `json:"config"`
	Actions    []string               `json:"actions"`
	DurationMS int                    `json:"duration_ms"`
}

type Emission struct {
	TS      string             `json:"ts"`
	Channel string             `json:"channel"`
	Data    map[string]float64 `json:"data"`
}

type RunLuaResponse struct {
	OK        bool               `json:"ok"`
	Emissions []Emission         `json:"emissions"`
	Metrics   map[string]float64 `json:"metrics"`
	Logs      []string           `json:"logs"`
	Errors    []string           `json:"errors"`
}

// EventSink is called as side-effects happen during RunLuaContext.
// kind is one of "emission", "log", "metric". Used by the NATS
// dispatcher to publish on agent.<id>.event.run-lua-progress as
// emissions arrive, instead of buffering.
//
// Pass nil to disable streaming — that's what HTTP does.
type EventSink func(kind string, payload map[string]any)

// --- Scan -----------------------------------------------------------------

// Scan executes a CIDR sweep + optional deep-probe of Modbus devices.
// Pure function — same body as the previous HTTP handler, but no
// http.ResponseWriter dependency.
func Scan(ctx context.Context, req ScanRequest) ScanResponse {
	cidr := req.CIDR
	if cidr == "" {
		cidr = scanner.LocalCIDR()
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = []int{502, 80, 1883}
	}
	resp := ScanResponse{Devices: []ScanDevice{}, Errors: []string{}}

	hosts, err := scanner.ScanSubnetMultiPort(cidr, ports, 1500*time.Millisecond)
	if err != nil {
		resp.Errors = append(resp.Errors, "tcp_sweep: "+err.Error())
		return resp
	}
	portsByIP := map[string][]int{}
	for _, h := range hosts {
		if !containsInt(portsByIP[h.IP], h.Port) {
			portsByIP[h.IP] = append(portsByIP[h.IP], h.Port)
		}
	}
	arpEntries, _ := scanner.ArpScan(cidr) // best-effort
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
		dev := ScanDevice{
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
	return resp
}

// --- Probe ----------------------------------------------------------------

// Probe reads a list of Modbus holding-register specs and decodes
// each value. Returns per-register errors inline (other registers
// still attempted).
func Probe(ctx context.Context, req ProbeRequest) (ProbeResponse, error) {
	if req.Protocol != "modbus" {
		return ProbeResponse{}, fmt.Errorf("only modbus probe supported in v0.1")
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
		return ProbeResponse{}, fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	resp := ProbeResponse{Results: []ProbeResultEntry{}, Errors: []string{}}
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
		resp.Results = append(resp.Results, ProbeResultEntry{
			Addr:   reg.Addr,
			Value:  val,
			RawHex: hex.EncodeToString(raw),
		})
	}
	return resp, nil
}

// --- RunLua ---------------------------------------------------------------

// RunLuaContext executes a Lua driver source in a sandboxed runtime.
// If sink is non-nil, every emission/log/metric is also delivered to
// the sink as it happens (same data is also accumulated into the
// returned response, so HTTP keeps its buffered behaviour).
//
// The NATS dispatcher passes a sink that publishes on
// agent.<id>.event.run-lua-progress, giving live progress to remote
// clients.
func RunLuaContext(ctx context.Context, req RunLuaRequest, sink EventSink) RunLuaResponse {
	if len(req.Actions) == 0 {
		req.Actions = []string{"init", "poll"}
	}
	resp := RunLuaResponse{
		Emissions: []Emission{},
		Metrics:   map[string]float64{},
		Logs:      []string{},
		Errors:    []string{},
	}
	if req.LuaSource == "" {
		resp.Errors = append(resp.Errors, "lua_source required")
		return resp
	}

	rt := luarunner.New()
	if err := rt.Init(); err != nil {
		resp.Errors = append(resp.Errors, "lua init: "+err.Error())
		return resp
	}
	defer rt.Close()

	emitFn := func(channel string, data map[string]float64) {
		copy := make(map[string]float64, len(data))
		for k, v := range data {
			copy[k] = v
		}
		ev := Emission{
			TS:      time.Now().UTC().Format(time.RFC3339),
			Channel: channel,
			Data:    copy,
		}
		resp.Emissions = append(resp.Emissions, ev)
		if sink != nil {
			sink("emission", map[string]any{
				"ts":      ev.TS,
				"channel": ev.Channel,
				"data":    ev.Data,
			})
		}
	}
	logFn := func(level, msg string) {
		line := "[" + level + "] " + msg
		resp.Logs = append(resp.Logs, line)
		if sink != nil {
			sink("log", map[string]any{
				"level":   level,
				"message": msg,
			})
		}
	}
	metricFn := func(name string, value float64) {
		resp.Metrics[name] = value
		if sink != nil {
			sink("metric", map[string]any{
				"name":  name,
				"value": value,
			})
		}
	}
	luarunner.RegisterStandardHostAPI(rt, emitFn, logFn, metricFn)
	luarunner.RegisterDecodeHostFuncs(rt)
	luarunner.RegisterMQTTStubs(rt)

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
		return resp
	}
	for _, action := range req.Actions {
		// Allow the caller to cancel mid-driver. ctx.Done is checked
		// between actions only; a runaway Lua script needs a separate
		// timeout (TODO).
		select {
		case <-ctx.Done():
			resp.Errors = append(resp.Errors, "cancelled: "+ctx.Err().Error())
			return resp
		default:
		}
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
	return resp
}

// configToLuaTable lifted unchanged from the old handler. Kept here
// (vs in luarunner) because it's a JSON↔Lua-table translation that
// only the request-handling layer needs.
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
