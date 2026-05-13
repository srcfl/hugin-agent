# hugin-agent

> Thin local helper for the [Hugin web app](https://hugin.sourceful-labs.net) — scans your LAN, talks Modbus, runs Lua drivers. Open. Stateless. Auditable.

## Why this exists

Hugin's web app at `hugin.sourceful-labs.net` lets you write Lua drivers for energy devices with the help of an AI. To actually **test** a draft against the real hardware on your network, the browser needs a way out — it can't speak Modbus TCP, it can't sweep ARP, it can't talk to your inverter.

This binary is that way out. It listens on `localhost:19090`, exposes five JSON endpoints, and does exactly the things the browser can't:

- Sweep your LAN for devices (TCP probe + ARP)
- Read Modbus holding-registers from an IP
- Execute a forty-two-watts-style Lua driver in a sandbox and stream the emissions back

Nothing else. No state stored on disk. No telemetry. No auto-update. No hidden background work. The whole binary is auditable in 30 minutes.

If you already run [forty-two-watts](https://github.com/frahlg/forty-two-watts), you don't need this — 42w can play the agent role itself (same protocol).

## Install

### macOS / Linux — Homebrew

```bash
brew install srcfl/tap/hugin-agent
hugin-agent
```

(Homebrew strips macOS quarantine automatically — no Gatekeeper warning.)

### Windows — Scoop

```powershell
scoop bucket add srcfl https://github.com/srcfl/scoop-bucket
scoop install hugin-agent
hugin-agent
```

### Docker

Published as a multi-arch image on every release tag. Use as a
sidecar in your existing compose stack (e.g. forty-two-watts):

```yaml
# docker-compose.hugin.yml
services:
  hugin-agent:
    image: ghcr.io/srcfl/hugin-agent:latest
    restart: unless-stopped
    network_mode: host          # see Modbus devices on the host LAN
    volumes:
      - hugin-agent-data:/var/lib/hugin-agent
volumes:
  hugin-agent-data:
```

```bash
docker compose -f docker-compose.hugin.yml up -d
docker logs hugin-agent          # the pairing URL is printed on stderr
```

`/var/lib/hugin-agent/creds.json` persists NATS pairing across
restarts. Without `network_mode: host` the agent can still talk to
the workbench (publish port 19090) but won't see Modbus devices on
the user's LAN — pick whichever fits your security model.

### From source (any platform with Go 1.25+)

```bash
go install github.com/srcfl/hugin-agent/cmd/hugin-agent@latest
hugin-agent
```

### Pre-built tarball

Direct downloads at [github.com/srcfl/hugin-agent/releases](https://github.com/srcfl/hugin-agent/releases). On macOS, you'll need to run `xattr -d com.apple.quarantine /path/to/hugin-agent` to bypass Gatekeeper for the unsigned binary — this is exactly what Homebrew does for you.

### Audit before you run

```bash
git clone https://github.com/srcfl/hugin-agent
cd hugin-agent
# read everything in cmd/ and internal/ — it's small
go build ./cmd/hugin-agent
./hugin-agent
```

## Pair with Hugin

When you start the agent it prints something like:

```
  Hugin agent v0.1.0
  Listening on http://127.0.0.1:19090
  Pairing token: a3f9c2d8e7b1f0a4c5d6e8f7a1b2c3d4

  Pair this agent with the web app:
    1. Open https://hugin.sourceful-labs.net/settings.html
    2. Paste the URL above + this token
    3. Click 'Test connection' then 'Save pairing'
```

Open the URL, paste both fields, save. The web app stores the pair in your browser's `localStorage` (never sent to Sourceful's servers). After that, the chat page at `hugin.sourceful-labs.net/chat.html` shows a green "agent" pill in the header and unlocks "Scan my LAN" + "Test latest driver" buttons.

## Flags

| Flag        | Default     | Notes                                                      |
|-------------|-------------|------------------------------------------------------------|
| `--host`    | `127.0.0.1` | Use `0.0.0.0` only if you're running this on a Pi and want LAN access. |
| `--port`    | `19090`     |                                                            |
| `--token`   | (random)    | Persistent token if you want to skip re-pairing on restart |

Same values via env: `HUGIN_AGENT_HOST`, `HUGIN_AGENT_PORT`, `HUGIN_AGENT_TOKEN`.

## Protocol (v1)

All endpoints return JSON. Auth: every protected endpoint expects `Authorization: Bearer <token>` matching the pairing token.

### `GET /v1/info` (no auth)

```json
{
  "name": "hugin-agent",
  "version": "0.1.0",
  "protocol_version": 1,
  "capabilities": ["scan", "probe", "run-lua"]
}
```

### `GET /v1/health` (no auth)

```json
{ "status": "ok", "ts": "2026-05-02T08:30:00Z" }
```

### `POST /v1/scan` (auth)

Sweeps the local subnet for devices.

Request:

```json
{ "cidr": "192.168.1.0/24", "ports": [502, 80, 1883], "deep_probe": false }
```

Response:

```json
{
  "devices": [
    {
      "ip": "192.168.1.50",
      "mac": "AA:BB:CC:DD:EE:FF",
      "vendor_oui": "Sungrow",
      "open_ports": [502, 80],
      "modbus": { "fc43_make": "Sungrow", "fc43_model": "SH10RT" },
      "http_banner": "..."
    }
  ],
  "errors": []
}
```

If `deep_probe: true`, devices on TCP-502 also get a Modbus FC43 device-identification probe.

### `POST /v1/probe` (auth)

Reads holding-registers from a specific Modbus device.

Request:

```json
{
  "ip": "192.168.1.50",
  "protocol": "modbus",
  "modbus": {
    "port": 502,
    "slave_id": 1,
    "registers": [
      { "addr": 16384, "count": 2, "kind": "i32_be" },
      { "addr": 16386, "count": 1, "kind": "u16" }
    ]
  }
}
```

`kind` is one of: `u16`, `i16`, `u32_be`, `u32_le`, `i32_be`, `i32_le`, `f32_be`, `f32_le`.

### `POST /v1/run-lua` (auth)

Executes a forty-two-watts Lua driver and returns whatever it emits.

Request:

```json
{
  "lua_source": "DRIVER = {...} function driver_init(c) ... end function driver_poll() ... end",
  "config": { "host": "192.168.1.50", "port": 502, "slave_id": 1 },
  "actions": ["init", "poll"],
  "duration_ms": 30000
}
```

`actions` is run in order; defaults to `["init", "poll"]`. The Lua VM is sandboxed (no `os`/`io`/`debug`, no `require`/`load`/`dofile`); the only way out is the `host.*` table.

Response:

```json
{
  "ok": true,
  "emissions": [
    { "ts": "...", "channel": "meter", "data": { "power_w": -2500 } }
  ],
  "metrics": {},
  "logs": ["[info] driver_init done"],
  "errors": []
}
```

## Security model

**What the agent CAN do** with the token someone has stolen from your machine:

- Read your Modbus / HTTP-discoverable devices on the LAN it's bound to
- Send Modbus reads (no writes — `/v1/probe` is read-only; Lua can write but only to the host you give it)
- Execute Lua source you POST it (sandboxed)

**What the agent CAN'T do:**

- Reach the public internet (we never make outbound calls except the ones drivers explicitly issue via `host.http_get` / `host.http_post`)
- Persist anything to disk
- Auto-update itself
- Phone home with telemetry
- Run arbitrary Go code (only sandboxed Lua)

**Recommendations:**

- Default bind is `127.0.0.1` (only the same machine). Don't change it unless you understand the trade-off.
- Don't share your pairing token. Generate a new random one with each restart by leaving `--token` empty.
- The web app at `hugin.sourceful-labs.net` stores the token in browser localStorage — clear it from settings if you stop using Hugin.

## License

MIT. See [LICENSE](LICENSE).

## Issues, questions

[github.com/srcfl/hugin-agent/issues](https://github.com/srcfl/hugin-agent/issues)
