#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-release}"
case "$mode" in
  debug|release) ;;
  *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac

cmake -S "$repo_root" -B "$repo_root/build" -DTRACELENS_BUILD_BPF=ON
cmake --build "$repo_root/build" -j"$(nproc)"

cargo_args=(build --locked -p tracelens-core --bins)
target_dir=debug
if [[ "$mode" == release ]]; then
  cargo_args+=(--release)
  target_dir=release
fi
cargo "${cargo_args[@]}" --manifest-path "$repo_root/Cargo.toml"

resource_root="$repo_root/ui/src-tauri/resources"
install -d "$resource_root/bin" "$resource_root/bpf/objects" "$resource_root/lib"
install -m 0755 "$repo_root/target/$target_dir/tracelens-core" "$resource_root/bin/tracelens-core"
install -m 0644 "$repo_root"/build/bpf/objects/*.o "$resource_root/bpf/objects/"

# Core is bundled as a resource executable, so AppImage tooling does not scan
# its dependencies. Ship the small non-glibc runtime libraries next to it and
# give Core an origin-relative lookup path. Debian packages may use the same
# copies, which also keeps the desktop runtime deterministic.
ldconfig_bin="$(command -v ldconfig || true)"
[[ -n "$ldconfig_bin" ]] || ldconfig_bin=/usr/sbin/ldconfig
for library in libelf.so.1 libz.so.1 libzstd.so.1; do
  path="$("$ldconfig_bin" -p | awk -v name="$library" '$1 == name && /x86-64/ && !found { path=$NF; found=1 } END { print path }')"
  [[ -n "$path" ]] || { echo "missing runtime library: $library" >&2; exit 1; }
  install -m 0644 "$path" "$resource_root/lib/$library"
done
patchelf --set-rpath '$ORIGIN/../lib' "$resource_root/bin/tracelens-core"

echo "Desktop resources prepared from $target_dir build"
