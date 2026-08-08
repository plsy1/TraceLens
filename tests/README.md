# Integration tests

The `telemetry_flow` integration test exercises the core pipeline without
requiring root privileges or a live kernel probe:

```text
ProcessExec → DNS Response → TCP Connect → TCP State → TCP Bytes → TCP Close
```

It verifies process snapshots, FakeIP/domain correlation, resolver-process
fallback, TCP state and byte aggregation, TTL expiry, closed-connection
history after process exit, and the `/api/timeline` JSON contract.

The timeline API contract also covers PID/event-kind/connection filtering and
page metadata (`total`, `offset`, and `has_more`). Storage coverage verifies
that the default memory-only mode does not create a database file; the opt-in
durable mode reopens SQLite and verifies that timeline and process state return.

Observation coverage exercises the command API and target-level L1-L5 state.

Connection timeline coverage verifies canonical connection IDs, DNS context
inside a session, grouped TCP events, lazy event payloads, capped session
details, and the `/api/connection-timeline` API.

HTTP coverage verifies bounded HTTP/1.1 request/response parsing, partial
header reassembly, Content-Length framing, L4 raw-capture dropping, and HTTP
metadata projection into the connection Timeline.

The future privileged acceptance test will launch `curl` against the real
observer and verify the kernel probe/API path end to end.
