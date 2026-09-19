#!/usr/bin/env bash
# Sign a GoReleaser release:
#   - checksums.txt gets a Sigstore blob-signature bundle
#   - every archive gets an SLSA v1 provenance attestation (per-archive
#     subject = the archive digest; source resolvedDependency = the exact
#     tag commit)
#   - every archive gets a CycloneDX SBOM describing the archive itself
#     (main component github.com/marcus/sidecar at the tag, archive SHA-256,
#     VCS reference pinned to the tag commit) and a signature bundle
#
# Keyless mode (CI, default): the workflow must hold id-token: write. Cosign
# exchanges the GitHub Actions OIDC token for a Fulcio certificate and records
# the entry in Rekor; everything needed for later *offline* verification is
# written into the *.bundle files (certificate chain, Rekor inclusion proof).
#
# Local-key mode (tests only): --key cosign.key. Produced bundles deliberately
# contain no transparency-log entry; consumers verify them with
# `--insecure-ignore-tlog` against the matching public key. Nothing published
# to users is ever produced in this mode.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: release-attest.sh DIST TAG COMMIT REPO RUN_ID [--key cosign.key]

  DIST     GoReleaser dist directory (archives + checksums.txt)
  TAG      release tag, strict vX.Y.Z
  COMMIT   full 40-hex commit the tag points at
  REPO     owner/name (e.g. marcus/sidecar)
  RUN_ID   GitHub Actions run id (any non-empty label in --key mode)
EOF
  exit 2
}

[[ $# -ge 5 ]] || usage
DIST=$1
TAG=$2
COMMIT=$3
REPO=$4
RUN_ID=$5
shift 5
KEY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)
      [[ $# -ge 2 ]] || usage
      KEY=$2
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done

[[ -d $DIST ]] || { echo "dist directory does not exist: $DIST" >&2; exit 1; }
[[ $TAG =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo "TAG must be strict SemVer vX.Y.Z: $TAG" >&2
  exit 1
}
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || {
  echo "COMMIT must be a 40-hex SHA: $COMMIT" >&2
  exit 1
}
[[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "REPO must be owner/name: $REPO" >&2
  exit 1
}
[[ -n $RUN_ID ]] || { echo "RUN_ID must not be empty" >&2; exit 1; }
[[ -f $DIST/checksums.txt ]] || {
  echo "missing $DIST/checksums.txt (run GoReleaser first)" >&2
  exit 1
}

for tool in cosign jq syft tar; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "required tool not found on PATH: $tool" >&2
    exit 1
  }
done

shasum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

temporary=$(mktemp -d)
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT

# All four archives must exist before signing anything: a release with half a
# matrix attested is a release nobody can verify.
find "$DIST" -mindepth 1 -maxdepth 1 -type f -name '*.tar.gz' \
  | LC_ALL=C sort >"$temporary/archives"
archive_count=$(wc -l <"$temporary/archives" | tr -d ' ')
[[ $archive_count -eq 4 ]] || {
  echo "expected exactly 4 archives in $DIST, found $archive_count" >&2
  exit 1
}
while IFS= read -r archive; do
  for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
    [[ $(basename "$archive") == *"_$target.tar.gz" ]] && continue 2
  done
  echo "unexpected archive name: $(basename "$archive")" >&2
  exit 1
done <"$temporary/archives"

# Cosign invocation helpers. --yes keeps keyless signing non-interactive under
# ambient GitHub Actions OIDC; the key path also accepts an unencrypted test
# key when COSIGN_PASSWORD is empty.
cosign_key_args=()
if [[ -n $KEY ]]; then
  [[ -f $KEY ]] || { echo "key file does not exist: $KEY" >&2; exit 1; }
  cosign_key_args=(--key "$KEY")
fi

sign_blob() {
  local file=$1 bundle=$2
  COSIGN_PASSWORD=${COSIGN_PASSWORD:-} cosign sign-blob \
    "${cosign_key_args[@]}" --bundle "$bundle" --yes "$file" >/dev/null
}

attest_blob() {
  local blob=$1 bundle=$2 predicate=$3
  COSIGN_PASSWORD=${COSIGN_PASSWORD:-} cosign attest-blob \
    "${cosign_key_args[@]}" --bundle "$bundle" \
    --predicate "$predicate" --type slsaprovenance1 --yes "$blob" >/dev/null
}

repo_url="https://github.com/$REPO"
workflow_ref="refs/tags/$TAG"
builder_id="$repo_url/.github/workflows/release.yml@$workflow_ref"
invocation_id="$repo_url/actions/runs/$RUN_ID"
started_on=$(date -u +%Y-%m-%dT%H:%M:%SZ)

index=0
while IFS= read -r archive; do
  index=$((index + 1))
  archive_file=$(basename "$archive")
  archive_sha=$(shasum "$archive")

  # The checksums file is verified independently by consumers; an archive
  # digest disagreement between these two paths is a failed install.
  if ! awk -v name="$archive_file" -v sha="$archive_sha" \
    '$2 == name && $1 == sha {found=1} END{exit !found}' \
    "$DIST/checksums.txt"; then
    echo "$archive_file is absent or mismatched in checksums.txt" >&2
    exit 1
  fi

  unpack="$temporary/unpack-$index"
  mkdir "$unpack"
  tar -xzf "$archive" -C "$unpack"

  # Syft catalogs the binary's embedded Go build information (main module +
  # dependencies). Scan the extracted tree, then overwrite metadata.component
  # so the BOM unambiguously describes *this archive*: main module pinned to
  # the tag, archive digest and VCS reference pinned to the tag commit.
  raw_sbom="$temporary/$archive_file.raw.cdx.json"
  sbom_file="$archive_file.sbom.cdx.json"
  sbom_path="$DIST/$sbom_file"
  syft "dir:$unpack" -o cyclonedx-json --quiet >"$raw_sbom" 2>/dev/null

  jq -c \
    --arg name "github.com/marcus/sidecar" \
    --arg version "$TAG" \
    --arg archive "$archive_file" \
    --arg archive_sha "$archive_sha" \
    --arg commit "$COMMIT" \
    --arg vcs "$repo_url@$COMMIT" \
    '
    .specVersion = (.specVersion // "1.5")
    | .metadata = (.metadata // {})
    | .metadata.component = {
        type: "application",
        name: $name,
        version: $version,
        purl: ("pkg:golang/" + $name + "@" + $version),
        hashes: [{alg: "SHA-256", hash: $archive_sha}],
        externalReferences: [{type: "vcs", url: $vcs}]
      }
    | .metadata.properties = ((.metadata.properties // []) + [
        {name: "sidecar:release-archive", value: $archive},
        {name: "sidecar:archive-sha256", value: $archive_sha},
        {name: "sidecar:source-commit", value: $commit}
      ])
    ' "$raw_sbom" >"$sbom_path"

  sign_blob "$sbom_path" "$sbom_path.bundle"
  sbom_sha=$(shasum "$sbom_path")

  # SLSA v1 provenance. externalParameters/ref and the source
  # resolvedDependency pin repo, tag and commit; the SBOM is recorded as a
  # byproduct so the signed predicate names its exact digest.
  predicate="$temporary/$archive_file.predicate.json"
  jq -nc \
    --arg repository "$repo_url" \
    --arg ref "$workflow_ref" \
    --arg commit "$COMMIT" \
    --arg builder "$builder_id" \
    --arg invocation "$invocation_id" \
    --arg started "$started_on" \
    --arg sbom_name "sbom:cyclonedx-json:$sbom_file" \
    --arg sbom_uri "$repo_url/releases/download/$TAG/$sbom_file" \
    --arg sbom_sha "$sbom_sha" \
    '{
      buildDefinition: {
        buildType: "https://github.com/marcus/sidecar/sidecar-goreleaser-release/v1",
        externalParameters: {
          repository: $repository,
          ref: $ref,
          workflow: ".github/workflows/release.yml",
          trigger: "push"
        },
        resolvedDependencies: [
          {
            name: "source",
            uri: ($repository + "@" + $ref),
            digest: {gitCommit: $commit}
          }
        ]
      },
      runDetails: {
        builder: {id: $builder},
        metadata: {
          invocationId: $invocation,
          startedOn: $started
        },
        byproducts: [
          {
            name: $sbom_name,
            uri: $sbom_uri,
            digest: {sha256: $sbom_sha}
          }
        ]
      }
    }' >"$predicate"

  attest_blob "$archive" "$DIST/$archive_file.att.bundle" "$predicate"
  echo "attested $archive_file @ $COMMIT"
done <"$temporary/archives"

sign_blob "$DIST/checksums.txt" "$DIST/checksums.txt.bundle"
echo "signed checksums.txt"

if [[ -n $KEY ]]; then
  echo "local-key attestation complete (test material, not for publication)"
else
  echo "keyless attestation complete"
fi
