# Development scripts

This directory is reserved for repeatable setup, probe generation, and local
integration-test helpers. Keep scripts small and make them safe to run from a
clean checkout.

- `privileged-e2e.sh` starts an isolated root observer, verifies a scoped HTTPS
  capture through the unified OpenSSL Provider, runs the profile matrix, and
  confirms that Stop releases every Kernel and Userspace link.
- `profile-matrix.sh [API_BASE] [CORE_PID]` records attach latency, object/link
  counts, reader counts, and a short Core CPU sample for every built-in profile.
- `tls-provider-e2e.sh` runs local OpenSSL, GnuTLS, and NSS clients against one
  TLS fixture and requires both normalized HTTP directions from each Provider.
- `prepare-desktop.sh [debug|release]` builds Core and BPF objects, stages the
  executable/runtime resources consumed by Tauri, and patches the bundled
  Core's relative library lookup path. It is called automatically by
  `npm run desktop:dev` and `npm run desktop:build`.
- `verify-release-version.sh vMAJOR.MINOR.PATCH` rejects a release when the
  tag does not match Cargo, Tauri, npm, and npm-lock versions.
