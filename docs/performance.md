# Probe performance baseline

The repeatable benchmark is `scripts/profile-matrix.sh`; the privileged
end-to-end wrapper is `scripts/privileged-e2e.sh`. Measurements below were
taken on 2026-08-09 from a debug build on the development host. CPU is a short
sample that includes 50 health API requests, so it is useful for regression
comparison on the same host, not as a production capacity claim.

| Profile | Attach ms | Kernel links | Kernel objects | Userspace providers | Readers | uProbe links | Core CPU sample |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Process | 18.05 | 2 | 1 | 0 | 0 | 0 | 3.47% |
| Connections | 28.65 | 6 | 2 | 0 | 0 | 0 | 4.87% |
| Network | 31.75 | 18 | 2 | 0 | 0 | 0 | 6.19% |
| Web | 57.44 | 18 | 2 | 1 | 1 | 8 | 6.69% |
| Security | 60.80 | 19 | 3 | 1 | 1 | 5 | 15.46% |
| Custom Files | 24.12 | 3 | 2 | 0 | 0 | 0 | 9.68% |

The pre-modular baseline attached 31 Kernel links for every capture. Its Web
path additionally loaded seven userspace objects and created seven readers for
up to twelve modern OpenSSL links. A Web capture uses 18 Kernel links; each
detected TLS Provider adds one object, one reader, and only the symbol links
exported by that Provider for correct entry/return semantics. The table above
predates the multi-Provider catalog and should be regenerated for release
hardware with `scripts/profile-matrix.sh`.

The current data does not justify making an fentry, sockops, or cgroup backend
the default. Link count and object count have already been reduced without
changing the event ABI; backend replacement should wait for controlled
throughput and drop-rate measurements on representative workloads.

The privileged E2E verified the kernel-uProbe fallback, scoped HTTPS payload,
HTTP reconstruction, all profile link plans, and complete Stop detach. The
bpftime loader and grouped-provider protocol compile and are covered by unit
tests, but a real bpftime run remains environment-gated because bpftime is not
installed on this host. The adapter also rejects upstream versions that no
longer expose its required `trace` command, rather than claiming a false
attachment; support for the newer `load/start/attach` lifecycle is future work.
