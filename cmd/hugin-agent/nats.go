// nats.go wires hugin-agent into a remote NATS broker, opt-in.
//
// The HTTP listener (server.go) is the historical mode; this file is
// the newer "remote agent" mode. They run side-by-side. Either can be
// disabled at startup with --no-listen / --no-nats.
//
// Two-step lifecycle:
//
//  1. Registration: agent starts with --register --gh-token=<gh>
//     Calls POST {api}/v1/agents/register, gets a credential bundle,
//     writes it to ~/.config/hugin-agent/creds.json, exits.
//  2. Connect: agent starts (no flags). Reads creds.json, dials NATS,
//     subscribes to its agent.<id>.req.> tree, dispatches into
//     server.Scan / server.Probe / server.RunLuaContext.
//
// The flow is intentionally idempotent: if creds.json is missing the
// agent prints how to register; if it's expired the agent re-runs
// registration on the next start (TODO — for now we surface the
// nats-jwt expiry error and the user re-registers manually).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/srcfl/hugin-agent/internal/server"
)

// natsCreds is the on-disk shape of ~/.config/hugin-agent/creds.json.
// Mirror of the API's registerResponse — kept narrow so the agent
// stays decoupled from hugin-api's internals.
type natsCreds struct {
	AgentID    string `json:"agent_id"`
	NATSURL    string `json:"nats_url"`
	UserJWT    string `json:"user_jwt"`
	UserSeed   string `json:"user_seed"`
	AccountJWT string `json:"account_jwt,omitempty"`
	CredsFile  string `json:"creds_file"`
	ExpiresAt  int64  `json:"expires_at"`
	APIBase    string `json:"api_base"`
}

// defaultCredsPath returns the path we read/write creds at. Override
// with HUGIN_AGENT_CREDS to keep test runs out of the user's real
// config dir.
func defaultCredsPath() string {
	if v := os.Getenv("HUGIN_AGENT_CREDS"); v != "" {
		return v
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		cfg = "."
	}
	return filepath.Join(cfg, "hugin-agent", "creds.json")
}

// loadCreds reads creds.json. Returns os.ErrNotExist when missing so
// callers can branch cleanly.
func loadCreds(path string) (*natsCreds, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c natsCreds
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("decode creds: %w", err)
	}
	return &c, nil
}

func saveCreds(path string, c *natsCreds) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// 0600 — credentials. NKey seed inside.
	return os.WriteFile(path, body, 0o600)
}

// registerWithAPI POSTs to the API's /v1/agents/register and returns
// the resulting credential bundle. Same shape as natsCreds — we
// translate field-by-field to dodge JSON tag drift if either side
// ever evolves.
func registerWithAPI(ctx context.Context, apiBase, ghToken string) (*natsCreds, error) {
	if apiBase == "" {
		return nil, errors.New("api base URL required")
	}
	if ghToken == "" {
		return nil, errors.New("github token required (use --gh-token)")
	}
	url := strings.TrimRight(apiBase, "/") + "/v1/agents/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ghToken)
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call api: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register failed: %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out natsCreds
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}
	out.APIBase = apiBase
	return &out, nil
}

// natsRunner owns the live NATS connection + subscriptions. Its
// public surface is just New / Run / Close.
type natsRunner struct {
	nc      *nats.Conn
	creds   *natsCreds
	logger  *log.Logger
	subs    []*nats.Subscription
}

// connectNATS dials with the supplied creds. We pass the JWT + seed
// inline (UserJWTAndSeed) instead of writing a temp file because the
// API already returned them as fields on the JSON; reusing that
// avoids a creds-file roundtrip on every reconnect.
func connectNATS(ctx context.Context, c *natsCreds, lg *log.Logger) (*natsRunner, error) {
	if c.NATSURL == "" {
		return nil, errors.New("creds missing nats_url")
	}
	if c.UserJWT == "" || c.UserSeed == "" {
		return nil, errors.New("creds missing user_jwt or user_seed")
	}
	opts := []nats.Option{
		nats.Name("hugin-agent/" + c.AgentID),
		nats.UserJWTAndSeed(c.UserJWT, c.UserSeed),
		// Reconnect aggressively. Edge agents drop wifi all the time;
		// the broker should never be the reason a Lua test fails.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.PingInterval(20 * time.Second),
		nats.MaxPingsOutstanding(3),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			lg.Printf("nats: disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			lg.Printf("nats: reconnected to %s", nc.ConnectedUrl())
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			lg.Printf("nats: async error: %v", err)
		}),
	}
	nc, err := nats.Connect(c.NATSURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect %s: %w", c.NATSURL, err)
	}
	lg.Printf("nats: connected to %s as agent %s", nc.ConnectedUrl(), c.AgentID)
	return &natsRunner{nc: nc, creds: c, logger: lg}, nil
}

// run subscribes to req.* and starts publishing presence on a
// heartbeat. Blocks until ctx is done.
func (r *natsRunner) run(ctx context.Context) error {
	subjScan := r.subj("req.scan")
	subjProbe := r.subj("req.probe")
	subjRunLua := r.subj("req.run-lua")

	// Each handler decodes the inbound JSON, dispatches into the
	// shared internal/server functions, marshals the response, and
	// publishes it on the reply-inbox NATS sets up automatically
	// for request/reply.
	subS, err := r.nc.Subscribe(subjScan, r.makeHandler(handleScanMsg))
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", subjScan, err)
	}
	subP, err := r.nc.Subscribe(subjProbe, r.makeHandler(handleProbeMsg))
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", subjProbe, err)
	}
	subR, err := r.nc.Subscribe(subjRunLua, r.makeRunLuaHandler())
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", subjRunLua, err)
	}
	r.subs = []*nats.Subscription{subS, subP, subR}
	r.logger.Printf("nats: listening on %s.req.>", "agent."+r.creds.AgentID)

	// Presence heartbeat. Every 15s, publish on
	// agent.<id>.event.presence with a tiny status blob. Watchers
	// (web client, dashboard) treat 30s of silence as "agent down."
	go r.presenceLoop(ctx)

	<-ctx.Done()
	return nil
}

func (r *natsRunner) close() {
	for _, s := range r.subs {
		_ = s.Drain()
	}
	if r.nc != nil {
		_ = r.nc.Drain()
	}
}

// subj builds a fully-qualified subject under our agent prefix.
func (r *natsRunner) subj(suffix string) string {
	return "agent." + r.creds.AgentID + "." + suffix
}

// reqHandler is the type the per-method dispatchers implement.
// They get the raw payload + a context and produce a response
// payload (or an error which is wired into a JSON error envelope).
type reqHandler func(ctx context.Context, payload []byte) ([]byte, error)

// makeHandler wraps a reqHandler in the NATS msg-handler shape with
// JSON error envelope on failure. Used for short ops (scan, probe).
func (r *natsRunner) makeHandler(h reqHandler) nats.MsgHandler {
	return func(m *nats.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		resp, err := h(ctx, m.Data)
		if err != nil {
			resp = mustJSON(map[string]string{"error": err.Error()})
		}
		if m.Reply != "" {
			if err := m.Respond(resp); err != nil {
				r.logger.Printf("nats: respond %s: %v", m.Subject, err)
			}
		}
	}
}

// makeRunLuaHandler is special-cased: RunLuaContext takes an
// EventSink, and we publish each emission/log/metric live on
// agent.<id>.event.run-lua-progress so a remote browser can render
// emissions as they happen instead of waiting for the buffered
// response.
func (r *natsRunner) makeRunLuaHandler() nats.MsgHandler {
	return func(m *nats.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		var req server.RunLuaRequest
		if err := json.Unmarshal(m.Data, &req); err != nil {
			r.respondErr(m, fmt.Errorf("decode: %w", err))
			return
		}
		// Pull a request_id out of the envelope if the client sent
		// one — we put it on the progress events so the client can
		// correlate streamed events with the eventual reply.
		var envelope struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(m.Data, &envelope)

		evtSubj := r.subj("event.run-lua-progress")
		sink := func(kind string, payload map[string]any) {
			body := map[string]any{
				"kind":       kind,
				"request_id": envelope.RequestID,
				"agent_id":   r.creds.AgentID,
			}
			for k, v := range payload {
				body[k] = v
			}
			if err := r.nc.Publish(evtSubj, mustJSON(body)); err != nil {
				r.logger.Printf("nats: publish event: %v", err)
			}
		}
		resp := server.RunLuaContext(ctx, req, sink)
		if m.Reply != "" {
			body := mustJSON(map[string]any{
				"request_id": envelope.RequestID,
				"response":   resp,
			})
			if err := m.Respond(body); err != nil {
				r.logger.Printf("nats: respond run-lua: %v", err)
			}
		}
	}
}

func (r *natsRunner) respondErr(m *nats.Msg, err error) {
	if m.Reply == "" {
		return
	}
	_ = m.Respond(mustJSON(map[string]string{"error": err.Error()}))
}

// presenceLoop publishes a heartbeat. Best-effort; failures are
// logged once per minute to avoid log-spam during outages.
func (r *natsRunner) presenceLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	subj := r.subj("event.presence")
	var lastErrAt time.Time
	publish := func() {
		body := mustJSON(map[string]any{
			"agent_id": r.creds.AgentID,
			"ts":       time.Now().UTC().Format(time.RFC3339),
			"status":   "ok",
		})
		if err := r.nc.Publish(subj, body); err != nil {
			if time.Since(lastErrAt) > time.Minute {
				r.logger.Printf("nats: presence publish: %v", err)
				lastErrAt = time.Now()
			}
		}
	}
	publish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			publish()
		}
	}
}

// --- per-method dispatchers ------------------------------------------------

func handleScanMsg(ctx context.Context, payload []byte) ([]byte, error) {
	var req server.ScanRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("decode scan: %w", err)
	}
	return mustJSON(server.Scan(ctx, req)), nil
}

func handleProbeMsg(ctx context.Context, payload []byte) ([]byte, error) {
	var req server.ProbeRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("decode probe: %w", err)
	}
	resp, err := server.Probe(ctx, req)
	if err != nil {
		return nil, err
	}
	return mustJSON(resp), nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Last-ditch: a literal {"error":"..."} so subscribers can
		// still parse something.
		return []byte(fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
	return b
}
