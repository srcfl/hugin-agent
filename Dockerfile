# syntax=docker/dockerfile:1.6
#
# Dockerfile for hugin-agent — the local helper the workbench talks
# to. Published as ghcr.io/srcfl/hugin-agent:vX.Y.Z on every release
# tag via goreleaser (see .goreleaser.yml).
#
# Primary use case: bundling inside another product's docker-compose
# stack (e.g. forty-two-watts) as a sidecar. Single static Go binary,
# ~12 MB final image, no daemon, no telemetry.
#
# Browser auto-open is disabled by default in the container — there
# is no browser; the user opens the pairing URL on their host
# manually (or via the parent product's UI).

# ---- Build stage -----------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo docker)" \
    -o /out/hugin-agent ./cmd/hugin-agent/

# ---- Runtime stage ---------------------------------------------------------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S hugin \
    && adduser -S -G hugin -h /home/hugin hugin

COPY --from=builder /out/hugin-agent /usr/local/bin/hugin-agent

# Container-friendly defaults:
#   - HUGIN_AGENT_HOST=0.0.0.0 so the agent is reachable from outside
#     the container (the parent compose stack does port mapping or
#     network_mode: host). The pairing token is still the auth boundary.
#   - --no-browser passed via CMD because there's no browser to open.
#   - Creds persist under /var/lib/hugin-agent so docker-compose
#     volumes can keep them across container restarts.
ENV HUGIN_AGENT_HOST=0.0.0.0 \
    HUGIN_AGENT_PORT=19090 \
    HUGIN_AGENT_CREDS=/var/lib/hugin-agent/creds.json

RUN mkdir -p /var/lib/hugin-agent && chown hugin:hugin /var/lib/hugin-agent

USER hugin
WORKDIR /home/hugin
VOLUME ["/var/lib/hugin-agent"]

EXPOSE 19090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${HUGIN_AGENT_PORT}/v1/health" \
        | grep -q '"status":"ok"' || exit 1
# /v1/health is intentionally unauthenticated (see internal/server/server.go) —
# the agent's pairing-token gate sits on the work endpoints (scan, probe,
# run-lua), not on liveness probes.

ENTRYPOINT ["hugin-agent"]
CMD ["--no-browser"]
