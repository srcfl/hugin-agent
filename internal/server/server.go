// Package server is the thin HTTP surface of hugin-agent: five
// endpoints that map directly onto the protocol the Hugin web app
// (https://hugin.sourceful-labs.net) speaks.
//
// The real work lives in handlers.go (Scan, Probe, RunLuaContext) as
// plain Go functions so the NATS dispatcher in cmd/hugin-agent/nats.go
// can share the same implementation. This file is just the JSON +
// auth shell.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"time"
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

// --- handlers (thin JSON wrappers around the pure funcs) -----------------

func handleInfo(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Info(version))
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, Health())
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	writeJSON(w, http.StatusOK, Scan(r.Context(), req))
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	var req ProbeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	resp, err := Probe(r.Context(), req)
	if err != nil {
		// Distinguish protocol-validation (400) from upstream/connect
		// failures (502). Probe currently surfaces both as plain
		// errors; we use the message to disambiguate. Cleaner long
		// term: typed sentinel errors.
		status := http.StatusBadGateway
		if err.Error() == "only modbus probe supported in v0.1" {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleRunLua(w http.ResponseWriter, r *http.Request) {
	var req RunLuaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	if req.LuaSource == "" {
		writeError(w, http.StatusBadRequest, "lua_source required")
		return
	}
	// HTTP path: no event sink. Caller gets the buffered response.
	writeJSON(w, http.StatusOK, RunLuaContext(r.Context(), req, nil))
}

// --- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
