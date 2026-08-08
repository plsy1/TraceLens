# Integration tests

The `telemetry_flow` integration test exercises the core pipeline without
requiring root privileges or a live kernel probe:

```text
ProcessExec → DNS Response → TCP Connect → TCP State → TCP Bytes → TCP Close
```

It verifies process snapshots, FakeIP/domain correlation, resolver-process
fallback, TCP state and byte aggregation, TTL expiry, closed-connection
history after process exit, and the `/api/timeline` JSON contract.

The timeline API contract also covers PID/event-kind filtering and page
metadata (`total`, `offset`, and `has_more`).

The future privileged acceptance test will launch `curl` against the real
observer and verify the kernel probe/API path end to end.
