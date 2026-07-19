# Hugin Agent workbench direction

Status: direction and TODOs only. No protocol or runtime behavior changes in
this PR.

## Decision

Hugin Agent may later be the local hardware execution plane for the Hugin
workbench. It discovers and probes devices, runs tightly constrained draft
tests and returns evidence. It is not a driver registry, canonical source,
package signer, package publisher, fleet installer or production control host.

`srcful-device-support` owns canonical driver source, versions, permissions and
signed target artifacts. FTW and Blixt L1 own their production runtimes and
safety. The agent must not imply that a draft tested in its current GopherLua
harness is proven for Blixt LuaJIT, FTW Core or a future Zap runtime.

## What exists today

- A small Go service with LAN scanning, Modbus probing and Lua execution.
- Local bearer-token pairing plus remote/NATS pairing paths.
- A GopherLua sandbox and host calls that can reach a selected LAN device.
- JSON responses containing emissions, metrics, logs and errors.

These are useful workbench building blocks. The current ability for posted Lua
to perform write-capable calls is not an acceptable default for an untrusted
driver-drafting workflow.

## TODO before implementation resumes

- [ ] Version a workbench-agent protocol independently from all production
      driver host APIs.
- [ ] Make discovery, probe and draft execution read-only by default. Enforce
      package/work-order permissions at each host call, not only in UI text.
- [ ] Add instruction, wall-clock, memory, response-size and network budgets;
      terminate a draft cleanly when any budget expires.
- [ ] Restrict Modbus/HTTP/MQTT destinations to the explicitly approved device
      and deny redirects or lateral LAN access by default.
- [ ] Return structured test results: target profile, exact source/package
      hash, device identity, calls performed, telemetry/sign assertions,
      timing, logs, errors and incomplete/timeout status.
- [ ] Add a Device Support package-verification mode for read-only reference
      artifacts. Verification must never install or activate production code.
- [ ] Treat FTW GopherLua and Blixt LuaJIT as separate adapters/test lanes;
      report unsupported target semantics instead of approximating success.
- [ ] Require an explicit, short-lived, physically confirmed work order before
      any future control test. It must include default-mode recovery, bounded
      lease expiry and structured command outcomes.
- [ ] Reconcile local and NATS pairing documentation, persisted credentials,
      rotation/revocation and offline behavior before calling the agent
      stateless or remote-safe.
- [ ] Define auditable update and binary provenance for the agent itself,
      separate from Device Support driver updates.

## Pilot gate

The first resumed pilot should be SDM630 telemetry only: bounded Modbus reads,
no writes, canonical site-import-positive assertions and an exportable evidence
bundle for a Device Support PR. Control hardware follows only after the shared
safety lifecycle and HIL plan are accepted. Zap remains future scope.
