# Releasing TraceLens

TraceLens releases are reproducible from an immutable Git tag. A release
binary must never be built from a moving `main` checkout after its tag has
been published.

## Version contract

The release version is shared by the Rust workspace, desktop crate, Tauri
bundle, npm package, and npm lockfile. Before tagging, update all version
sources and verify them with:

```bash
./scripts/verify-release-version.sh v0.0.1
```

Cargo and npm lockfiles must be committed. Release jobs use `--locked` or
`npm ci` and fail instead of silently rewriting dependency resolution.

## Publish a release

1. Merge the release commit into `main` and wait for CI to pass.
2. Update the local `main` branch.
3. Create an annotated semantic-version tag on that commit.
4. Push only the tag.

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.0.1 -m "TraceLens v0.0.1"
git push origin v0.0.1
```

`.github/workflows/release.yml` rejects malformed versions and tags whose
commit is not reachable from `origin/main`. It runs locked Rust tests,
Clippy, the UI build, BPF and desktop preparation, then builds Linux packages
on Ubuntu 22.04. The workflow inspects the Debian package, requires all seven
BPF objects, generates `SHA256SUMS`, stores a workflow artifact, and creates a
draft GitHub Release. The draft is published only after every asset upload
succeeds. A rerun may repair a draft but never replaces an already published
release.

## Linux compatibility policy

The initial release target is Linux x86_64:

- `.deb`: Debian 12 or newer and Ubuntu 22.04 or newer.
- AppImage: portable fallback for other desktop distributions with Polkit.
- Kernel validation: Ubuntu 22.04 (5.15), Debian 12 (6.1), and Ubuntu 24.04
  (6.8) are the first acceptance matrix.

Building on Ubuntu 22.04 establishes an older glibc baseline than a developer
machine running Debian 13. AppImage does not remove the glibc baseline, and it
still expects `/usr/bin/pkexec` plus a desktop Polkit authentication agent.
Kernel CO-RE reduces distribution-specific probe builds, but supported hosts
still need BTF and the BPF/uprobe capabilities used by TraceLens.

RPM, Flatpak, native Arch packages, and aarch64 are separate release targets.
They should be added only with native install/start/capture/exit tests; they
must not be represented by renaming the Debian artifact.

## Local release-equivalent build

```bash
cd ui
npm ci
npm audit --audit-level=moderate
npm run desktop:build -- --ci
```

The resulting packages are under `ui/src-tauri/target/release/bundle/`.
