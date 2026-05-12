package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/hugin-agent/internal/server"
)

func TestHandleInfoMsg(t *testing.T) {
	// req.info dispatcher returns the version surfaced on the runner.
	// Workbench reads the version field to render "agent v0.2.0
	// connected" on the pairing card.
	r := &natsRunner{version: "v0.2.0-test"}
	out, err := r.handleInfoMsg(context.Background(), nil)
	if err != nil {
		t.Fatalf("handleInfoMsg: %v", err)
	}
	var got server.InfoResponse
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode info: %v", err)
	}
	if got.Name != "hugin-agent" {
		t.Errorf("name: got %q", got.Name)
	}
	if got.Version != "v0.2.0-test" {
		t.Errorf("version: got %q", got.Version)
	}
	if got.ProtocolVersion != 1 {
		t.Errorf("protocol_version: got %d", got.ProtocolVersion)
	}
	wantCaps := map[string]bool{"scan": true, "probe": true, "run-lua": true}
	for _, c := range got.Capabilities {
		if !wantCaps[c] {
			t.Errorf("unexpected capability %q", c)
		}
		delete(wantCaps, c)
	}
	if len(wantCaps) != 0 {
		t.Errorf("missing capabilities: %v", wantCaps)
	}
}

func TestHandleHealthMsg(t *testing.T) {
	out, err := handleHealthMsg(context.Background(), nil)
	if err != nil {
		t.Fatalf("handleHealthMsg: %v", err)
	}
	var got server.HealthResponse
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("status: got %q", got.Status)
	}
	if _, err := time.Parse(time.RFC3339, got.TS); err != nil {
		t.Errorf("ts not RFC3339: %q (%v)", got.TS, err)
	}
}

func TestWarnIfCredsNearExpiry(t *testing.T) {
	// Each case captures stderr to verify whether the warning fires.
	// The exact message wording is not asserted — only presence vs
	// absence and the "expired" branch.
	cases := []struct {
		name          string
		expiresIn     time.Duration
		expiresAtZero bool
		expectWarn    bool
		expectExpired bool
	}{
		{"no expiry recorded", 0, true, false, false},
		{"fresh creds (30d)", 30 * 24 * time.Hour, false, false, false},
		{"fresh creds (8d)", 8 * 24 * time.Hour, false, false, false},
		{"inside renewal window (6d)", 6 * 24 * time.Hour, false, true, false},
		{"inside renewal window (1h)", 1 * time.Hour, false, true, false},
		{"expired 1m ago", -1 * time.Minute, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			creds := &natsCreds{}
			if !tc.expiresAtZero {
				creds.ExpiresAt = now.Add(tc.expiresIn).Unix()
			}
			out := captureStderr(t, func() { warnIfCredsNearExpiry(creds, now) })
			gotWarn := strings.Contains(out, "Renew with: hugin-agent --register")
			if gotWarn != tc.expectWarn {
				t.Errorf("warn=%v want=%v, output=%q", gotWarn, tc.expectWarn, out)
			}
			gotExpired := strings.Contains(out, "expired")
			if gotExpired != tc.expectExpired {
				t.Errorf("expired-branch=%v want=%v, output=%q", gotExpired, tc.expectExpired, out)
			}
		})
	}
}

// TestWarnIfCredsNearExpiry_NilSafe is a defensive check — a nil
// creds pointer reaches this function if loadCreds returned an
// error but main.go forgot to bail. Must not panic.
func TestWarnIfCredsNearExpiry_NilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on nil creds: %v", r)
		}
	}()
	warnIfCredsNearExpiry(nil, time.Now())
}

func TestServerInfoAndHealth(t *testing.T) {
	// The pure funcs in internal/server are the shared truth across
	// HTTP and NATS — keep a smoke test that pins the shape.
	info := server.Info("vX")
	if info.Name != "hugin-agent" || info.Version != "vX" || info.ProtocolVersion != 1 {
		t.Errorf("info: %+v", info)
	}
	if len(info.Capabilities) != 3 {
		t.Errorf("capabilities: %v", info.Capabilities)
	}
	health := server.Health()
	if health.Status != "ok" {
		t.Errorf("health.Status: %q", health.Status)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and
// returns whatever was written. We use a real OS pipe (not a
// bytes.Buffer) because fmt.Fprintln writes through the file
// descriptor.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	fn()
	_ = w.Close()
	<-done
	_ = r.Close()
	return buf.String()
}
