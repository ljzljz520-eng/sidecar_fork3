#!/usr/bin/env bash
# Offline verification of every asset in a published release directory:
#   - checksums.txt signature
#   - per-archive SLSA provenance attestation (subject = archive digest)
#   - per-archive signed SBOM (main module version + archive digest + commit)
# All four archives (darwin/linux x amd64/arm64) must verify and pin the SAME
# Git commit. The only inputs are the materials themselves and the Sigstore
# trusted root vendored in this repository: no network calls are made.
#
# Usage:
#   verify-release-trust.sh DIR TAG [COMMIT] [--key cosign.pub]
#
# --key selects local public-key verification (test fixtures only); the
# default verifies keyless Fulcio identities exactly like setup.sh.
set -euo pipefail

usage() {
  echo "usage: $0 DIR TAG [COMMIT] [--key cosign.pub]" >&2
  exit 2
}

[[ $# -ge 2 ]] || usage
DIR=$1
TAG=$2
shift 2
EXPECTED_COMMIT=""
KEY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)
      [[ $# -ge 2 ]] || usage
      KEY=$2
      shift 2
      ;;
    *)
      if [[ -z "$EXPECTED_COMMIT" ]]; then
        EXPECTED_COMMIT=$1
        shift
      else
        usage
      fi
      ;;
  esac
done

[[ -d $DIR ]] || { echo "release directory does not exist: $DIR" >&2; exit 1; }
[[ $TAG =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo "TAG must be strict SemVer vX.Y.Z: $TAG" >&2
  exit 1
}
if [[ -n $EXPECTED_COMMIT && ! $EXPECTED_COMMIT =~ ^[0-9a-f]{40}$ ]]; then
  echo "COMMIT must be a 40-hex SHA: $EXPECTED_COMMIT" >&2
  exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
trusted_root="$repo_root/packaging/sigstore/trusted_root.json"
[[ -f $trusted_root ]] || { echo "missing trusted root: $trusted_root" >&2; exit 1; }

# Reuse the installer's verification implementation verbatim: if these two
# ever diverge, CI says green while users fail.
SIDECAR_SETUP_NO_MAIN=1
# shellcheck source=scripts/setup.sh
source "$repo_root/scripts/setup.sh"

command -v cosign >/dev/null 2>&1 || {
  echo "cosign not found on PATH" >&2
  exit 1
}
if [[ -n $KEY ]]; then
  [[ -f $KEY ]] || { echo "key file does not exist: $KEY" >&2; exit 1; }
  export SIDECAR_VERIFY_KEY=$KEY
  trusted_root=""
fi

temporary=$(mktemp -d)
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT

# Copy every material into per-platform working directories so the verifier
# sees the same file layout an installed release presents on disk.
targets=(darwin_amd64 darwin_arm64 linux_amd64 linux_arm64)
commits=()
for target in "${targets[@]}"; do
  archive="sidecar_${TAG#v}_${target}.tar.gz"
  [[ -f "$DIR/$archive" ]] || { echo "missing archive: $archive" >&2; exit 1; }

  work="$temporary/$target"
  mkdir "$work"
  cp "$DIR/$archive" \
     "$DIR/checksums.txt" \
     "$DIR/checksums.txt.bundle" \
     "$DIR/$archive.att.bundle" \
     "$DIR/$archive.sbom.cdx.json" \
     "$DIR/$archive.sbom.cdx.json.bundle" \
     "$work/"

  commit=$(verify_release_materials \
    "$work" "$archive" "$SIDECAR_REPO" "$TAG" cosign "$trusted_root")
  [[ -n $commit ]] || { echo "$target: verifier returned no commit" >&2; exit 1; }
  commits+=("$commit")
  echo "verified $archive -> $commit"
done

first=${commits[0]}
for commit in "${commits[@]}"; do
  [[ $commit == "$first" ]] || {
    echo "provenance commits disagree across archives" >&2
    printf '  %s\n' "${commits[@]}" >&2
    exit 1
  }
done

if [[ -n $EXPECTED_COMMIT && $first != "$EXPECTED_COMMIT" ]]; then
  echo "provenance commit $first does not match expected $EXPECTED_COMMIT" >&2
  exit 1
fi

echo "all 4 assets verify offline to ${first} (SBOM main module ${TAG})"
