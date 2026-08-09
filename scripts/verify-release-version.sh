#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${1:-}"
if [[ ! "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "release tag must use vMAJOR.MINOR.PATCH, got: ${tag:-<empty>}" >&2
  exit 1
fi
expected="${tag#v}"

toml_version() {
  awk -F'"' '/^version = "/ { print $2; exit }' "$1"
}

json_version() {
  awk -F'"' '$2 == "version" { print $4; exit }' "$1"
}

declare -A versions=(
  [workspace]="$(toml_version "$repo_root/Cargo.toml")"
  [desktop-cargo]="$(toml_version "$repo_root/ui/src-tauri/Cargo.toml")"
  [desktop-tauri]="$(json_version "$repo_root/ui/src-tauri/tauri.conf.json")"
  [ui-npm]="$(json_version "$repo_root/ui/package.json")"
  [ui-lock]="$(json_version "$repo_root/ui/package-lock.json")"
)

failed=0
for component in "${!versions[@]}"; do
  actual="${versions[$component]}"
  if [[ "$actual" != "$expected" ]]; then
    echo "$component version is $actual; expected $expected from $tag" >&2
    failed=1
  fi
done
if (( failed )); then
  exit 1
fi

echo "release version verified: $tag"
