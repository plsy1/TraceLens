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

Capture coverage exercises Profile expansion, module dependencies, lifecycle
commands, Plaintext confirmation, and legacy Level compatibility translation.

Connection timeline coverage verifies canonical connection IDs, DNS context
inside a session, grouped TCP events, lazy event payloads, capped session
details, and the `/api/connection-timeline` API.

HTTP coverage verifies bounded HTTP/1.1 request/response parsing, partial
header reassembly, Content-Length framing, HTTP raw-capture dropping, and HTTP
metadata projection into the connection Timeline.

Privileged runtime coverage is separate from normal CI:

```bash
./scripts/privileged-e2e.sh
./scripts/tls-provider-e2e.sh
```

It launches `curl` against a real observer and verifies the Profile link
matrix, Provider object/reader ownership, scoped HTTPS-to-HTTP capture, and
complete Kernel/Userspace detach. `fixtures/nss_http_client.c` exercises the
NSS/NSPR object allowlist against a local TLS response, and
`fixtures/dlopen_tls.c` verifies delayed-library reconciliation.
