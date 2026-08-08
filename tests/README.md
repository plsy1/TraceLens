# Integration tests

The `telemetry_flow` integration test exercises the core pipeline without
requiring root privileges or a live kernel probe:

```text
ProcessExec → DNS Response → TCP Connect → TCP State → TCP Bytes → TCP Close
```

It verifies process snapshots, FakeIP/domain correlation, TCP state and byte
aggregation, TTL expiry, and closed-connection history after process exit.

The future privileged acceptance test will launch `curl` against the real
observer and verify the kernel probe/API path end to end.
