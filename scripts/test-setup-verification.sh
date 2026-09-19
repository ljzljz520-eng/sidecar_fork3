#!/usr/bin/env bash
# Acceptance tests for the Sidecar supply-chain hardening.
#
# Builds a complete signed release locally (local-key bundles for the
# tamper matrix, plus a synthetic Fulcio-equivalent CA that exercises the
# real certificate identity claims), serves it over loopback HTTP, and
# proves:
#
#   1. A single-byte tamper of any archive, checksums.txt, signature bundle,
#      provenance statement or SBOM is rejected BEFORE extraction, and an
#      existing sidecar binary stays byte-for-byte in place (atomic install).
#   2. A forged certificate identity / issuer / trigger / repo / ref /
#      workflow name / workflow SHA is rejected even when the attacker holds
#      a leaf key that chains to the trusted CA.
#   3. All four archives (darwin/linux x amd64/arm64) verify OFFLINE to the
#      same Git commit, with the SBOM main module pinned to that tag/commit.
#   4. A host without cosign on PATH completes a verified install through the
#      pinned-hash cosign bootstrap; a tampered bootstrap binary is refused.
#   5. Legacy releases with no provenance are refused by default and installed
#      only with the explicit --allow-legacy-binary flag.
#   6. Unreachable services fail closed: -y never falls back to a source
#      build; a source build happens only after an explicit interactive "y".
#   7. A clean Linux container (no Go, no cosign) completes a verified
#      install using the bootstrap path.
#   8. The Homebrew source-formula publication tests still pass.
#
# Env knobs:
#   SKIP_DOCKER=1   skip the clean Linux container section
#   SKIP_AMD64=1    skip the linux/amd64 (emulated) container pass
#   OPENSSL=PATH    openssl binary supporting arbitrary OID DER extensions
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TAG=v1.2.3
VER=1.2.3
COMMIT=0123456789abcdef0123456789abcdef01234567
REPO=marcus/sidecar
TARGETS="darwin_amd64 darwin_arm64 linux_amd64 linux_arm64"
# darwin_arm64 on Apple Silicon, linux_x86 elsewhere; override if needed.
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
    x86_64|amd64) HOST_ARCH=amd64 ;;
    arm64|aarch64) HOST_ARCH=arm64 ;;
    *) HOST_ARCH=unsupported ;;
esac
HOST_TARGET="${HOST_OS}_${HOST_ARCH}"

PASS=0
FAIL=0
FAILED_CASES=""
SECTION=""

note()  { printf '  \033[2m%s\033[0m\n' "$*"; }
ok()    { PASS=$((PASS+1)); printf '  \033[32mok\033[0m  %s\n' "$*"; }
bad()   { FAIL=$((FAIL+1)); FAILED_CASES="${FAILED_CASES}
    - [$SECTION] $*"; printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
section() { SECTION="$1"; printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
die() { printf 'fatal: %s\n' "$*" >&2; exit 2; }

assert_rc() { # expected actual description
    if [[ "$2" == "$1" ]]; then ok "$3 (rc=$2)"
    else bad "$3 (wanted rc=$1, got $2)"; fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Flip the first byte of a file (XOR 0x01) without touching its length.
flip_byte() {
    python3 - "$1" <<'PY'
import sys
p = sys.argv[1]
with open(p, "rb") as f:
    b = bytearray(f.read())
b[0] ^= 0x01
with open(p, "wb") as f:
    f.write(b)
PY
}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/sidecar-verify.XXXXXX")
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
section "prerequisites"
for tool in cosign curl tar python3 jq; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
COSIGN=$(command -v cosign)
ok "cosign at $COSIGN ($("$COSIGN" version 2>/dev/null | head -1))"

if [[ -z "${OPENSSL:-}" ]]; then
    for c in /opt/homebrew/opt/openssl@3/bin/openssl /opt/homebrew/bin/openssl "$(command -v openssl)"; do
        [[ -x "$c" ]] && { OPENSSL="$c"; break; }
    done
fi
[[ -n "${OPENSSL:-}" && -x "$OPENSSL" ]] || die "no openssl found"
ok "openssl at $OPENSSL ($("$OPENSSL" version))"

# ---------------------------------------------------------------------------
# Fixture: four archives, checksums, local-key signed materials (release-attest)
# ---------------------------------------------------------------------------
section "building key-signed release fixture"
KEYDIR="$TMP/keys"
DIST="$TMP/dist"
FAKEBIN="$TMP/fakebin"
mkdir -p "$KEYDIR" "$DIST" "$FAKEBIN"
(
    cd "$KEYDIR"
    COSIGN_PASSWORD="" "$COSIGN" generate-key-pair --output-key-prefix cosign >/dev/null 2>&1
)
[[ -s "$KEYDIR/cosign.key" && -s "$KEYDIR/cosign.pub" ]] || die "key generation failed"
ok "generated local cosign keypair"

for target in $TARGETS; do
    pkg="$TMP/pkg/$target"
    mkdir -p "$pkg"
    cat >"$pkg/sidecar" <<EOF
#!/bin/sh
echo "sidecar $VER $target"
EOF
    chmod 0755 "$pkg/sidecar"
    printf '# Sidecar\n%s fixture binary\n' "$target" >"$pkg/README.md"
    printf '# Changelog\n%s test release\n' "$TAG" >"$pkg/CHANGELOG.md"
    tar -C "$pkg" -czf "$DIST/sidecar_${VER}_${target}.tar.gz" .
done
( cd "$DIST" && for f in sidecar_*.tar.gz; do
      if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
  done > checksums.txt )
[[ $(wc -l < "$DIST/checksums.txt") -eq 4 ]] || die "checksums.txt should list 4 archives"
ok "built 4 archives + checksums.txt"

# Fake syft: emits minimal CycloneDX JSON; release-attest.sh fills component,
# version, purl, archive digest and VCS commit via jq.
cat >"$FAKEBIN/syft" <<'EOF'
#!/bin/sh
cat <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{}}
JSON
EOF
chmod +x "$FAKEBIN/syft"

PATH="$FAKEBIN:$PATH" COSIGN_PASSWORD="" \
    "$REPO_ROOT/scripts/release-attest.sh" "$DIST" "$TAG" "$COMMIT" "$REPO" localrun \
    --key "$KEYDIR/cosign.key" >"$TMP/attest-victim.log" 2>&1
for f in checksums.txt.bundle; do
    [[ -s "$DIST/$f" ]] || die "release-attest missing $f"
done
for target in $TARGETS; do
    for f in ".att.bundle" ".sbom.cdx.json" ".sbom.cdx.json.bundle"; do
        [[ -s "$DIST/sidecar_${VER}_${target}.tar.gz$f" ]] \
            || die "release-attest missing sidecar_${VER}_${target}.tar.gz$f"
    done
done
ok "release-attest.sh produced provenance + SBOM + bundles for 4 archives"

# Attacker keypair + a second fully-signed release (different trust root).
ATKDIR="$TMP/atk"
ATKDIST="$TMP/atkdist"
mkdir -p "$ATKDIR" "$ATKDIST"
( cd "$ATKDIR" && COSIGN_PASSWORD="" "$COSIGN" generate-key-pair --output-key-prefix cosign >/dev/null 2>&1 )
cp "$DIST"/sidecar_*.tar.gz "$DIST/checksums.txt" "$ATKDIST/"
PATH="$FAKEBIN:$PATH" COSIGN_PASSWORD="" \
    "$REPO_ROOT/scripts/release-attest.sh" "$ATKDIST" "$TAG" \
    "fedcba9876543210fedcba9876543210fedcba98" "$REPO" attackrun \
    --key "$ATKDIR/cosign.key" >"$TMP/attest-attacker.log" 2>&1
ok "built attacker-signed release (different key + commit)"

# ---------------------------------------------------------------------------
# Fixture: synthetic CA + workflow leaf, legacy bundles for all four archives
# ---------------------------------------------------------------------------
section "building synthetic Fulcio-equivalent PKI"
PKI="$TMP/pki"
mkdir -p "$PKI"
(
    cd "$PKI"
    "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
    cat >ca.cnf <<'EOF'
[v3ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF
    "$OPENSSL" req -new -key ca.key -subj "/CN=sidecar-test-ca" -out ca.csr 2>/dev/null
    "$OPENSSL" x509 -req -in ca.csr -signkey ca.key -days 3650 \
        -extfile ca.cnf -extensions v3ca -out ca.pem 2>/dev/null
    "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
    "$OPENSSL" req -new -key leaf.key -subj "/CN=sidecar-release" -out leaf.csr 2>/dev/null
)

# make_leaf NAME IDENTITY ISSUER TRIGGER SHA WORKFLOW REPO REF
make_leaf() {
    local name="$1" identity="$2" issuer="$3" trigger="$4" sha="$5" wf="$6" repo="$7" ref="$8"
    local cnf="$PKI/$name.cnf"
    hexval() { printf '%s' "$1" | xxd -p | tr -d '\n'; }
    cat >"$cnf" <<EOF
[v3leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
subjectAltName = URI:$identity
1.3.6.1.4.1.57264.1.1=DER:$(hexval "$issuer")
1.3.6.1.4.1.57264.1.2=DER:$(hexval "$trigger")
1.3.6.1.4.1.57264.1.3=DER:$(hexval "$sha")
1.3.6.1.4.1.57264.1.4=DER:$(hexval "$wf")
1.3.6.1.4.1.57264.1.5=DER:$(hexval "$repo")
1.3.6.1.4.1.57264.1.6=DER:$(hexval "$ref")
EOF
    "$OPENSSL" x509 -req -in "$PKI/leaf.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" \
        -CAcreateserial -days 3650 -extfile "$cnf" -extensions v3leaf \
        -out "$PKI/$name.pem" 2>/dev/null
}
IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"
ISSUER="https://token.actions.githubusercontent.com"
make_leaf leaf "$IDENTITY" "$ISSUER" push "$COMMIT" Release "$REPO" "refs/tags/$TAG"
[[ -s "$PKI/leaf.pem" ]] || die "leaf certificate generation failed (try OPENSSL=/path/to/openssl3)"

# Helper that wraps DER/ECDSA signatures and DSSE attestations in the legacy
# bundle format {"base64Signature": ..., "cert": PEM}. Signatures are produced
# with the same openssl key the leaf certificate was issued for.
cat >"$TMP/mklegacy.py" <<'PY'
import base64, json, subprocess, sys

def b64(b):
    return base64.b64encode(b).decode()

def sign(openssl, key, data):
    p = subprocess.run([openssl, "dgst", "-sha256", "-sign", key],
                       input=data, capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode())
        sys.exit(3)
    return p.stdout

def pem(path):
    return open(path).read()

def find_envelope(o):
    if isinstance(o, dict):
        if "payload" in o and "signatures" in o:
            return o
        for v in o.values():
            r = find_envelope(v)
            if r is not None:
                return r
    return None

cmd, openssl, key, cert = sys.argv[1:5]
cert_pem = pem(cert)

if cmd == "blob":
    data = open(sys.argv[5], "rb").read()
    out = sys.argv[6]
    bundle = {"base64Signature": b64(sign(openssl, key, data)), "cert": cert_pem}
elif cmd == "att":
    v03 = json.load(open(sys.argv[5]))
    out = sys.argv[6]
    env_in = find_envelope(v03)
    payload = base64.b64decode(env_in["payload"])
    payload_b64 = base64.b64encode(payload).decode()
    pae = b"DSSEv1 %d application/vnd.in-toto+json %d " % (
        len(b"application/vnd.in-toto+json"), len(payload)) + payload
    env = {"payloadType": "application/vnd.in-toto+json",
           "payload": payload_b64,
           "signatures": [{"keyid": "", "sig": b64(sign(openssl, key, pae))}]}
    bundle = {"base64Signature": b64(json.dumps(env, separators=(",", ":")).encode()),
              "cert": cert_pem}
elif cmd == "recommit":
    # Rewrite the provenance commit inside an existing legacy attestation
    # bundle WITHOUT re-signing: the stale signature must be detected.
    bundle = json.load(open(sys.argv[5]))
    out = sys.argv[6]
    env = json.loads(base64.b64decode(bundle["base64Signature"]))
    stmt = json.loads(base64.b64decode(env["payload"]))
    deps = stmt["predicate"]["buildDefinition"]["resolvedDependencies"]
    deps[0]["digest"]["gitCommit"] = "fedcba9876543210fedcba9876543210fedcba98"
    env["payload"] = base64.b64encode(
        json.dumps(stmt, separators=(",", ":")).encode()).decode()
    bundle["base64Signature"] = b64(
        json.dumps(env, separators=(",", ":")).encode())
else:
    sys.exit(2)

with open(out, "w") as f:
    json.dump(bundle, f, separators=(",", ":"))
PY
ok "synthetic CA + correct workflow leaf issued"

CERTDIST="$TMP/certdist"
mkdir -p "$CERTDIST"
cp "$DIST"/sidecar_*.tar.gz "$DIST/checksums.txt" "$CERTDIST/"
for target in $TARGETS; do
    a="sidecar_${VER}_${target}.tar.gz"
    python3 "$TMP/mklegacy.py" blob "$OPENSSL" "$PKI/leaf.key" "$PKI/leaf.pem" \
        "$DIST/checksums.txt" "$CERTDIST/checksums.txt.bundle"
    python3 "$TMP/mklegacy.py" blob "$OPENSSL" "$PKI/leaf.key" "$PKI/leaf.pem" \
        "$DIST/$a.sbom.cdx.json" "$CERTDIST/$a.sbom.cdx.json.bundle"
    python3 "$TMP/mklegacy.py" att "$OPENSSL" "$PKI/leaf.key" "$PKI/leaf.pem" \
        "$DIST/$a.att.bundle" "$CERTDIST/$a.att.bundle"
    cp "$DIST/$a.sbom.cdx.json" "$CERTDIST/"
done
ok "legacy (certificate-chain) bundles produced for all archives"

# Forged leaves: each one differs in exactly one identity claim.
BAD_SHA=fedcba9876543210fedcba9876543210fedcba98
make_leaf w-identity "https://github.com/evil-inc/sidecar/.github/workflows/release.yml@refs/tags/$TAG" \
    "$ISSUER" push "$COMMIT" Release "$REPO" "refs/tags/$TAG"
make_leaf w-issuer "$IDENTITY" "https://idp.evil.example" push "$COMMIT" Release \
    "$REPO" "refs/tags/$TAG"
make_leaf w-trigger "$IDENTITY" "$ISSUER" workflow_dispatch "$COMMIT" Release \
    "$REPO" "refs/tags/$TAG"
make_leaf w-sha "$IDENTITY" "$ISSUER" push "$BAD_SHA" Release \
    "$REPO" "refs/tags/$TAG"
make_leaf w-workflow "$IDENTITY" "$ISSUER" push "$COMMIT" Evil \
    "$REPO" "refs/tags/$TAG"
make_leaf w-repo "$IDENTITY" "$ISSUER" push "$COMMIT" Release \
    "evil-inc/sidecar" "refs/tags/$TAG"
make_leaf w-ref "$IDENTITY" "$ISSUER" push "$COMMIT" Release \
    "$REPO" "refs/tags/v9.9.9"
ok "issued 7 forged leaves (one claim wrong each)"

# ---------------------------------------------------------------------------
# Shared harness: run setup.sh functions in a clean sourced shell
# ---------------------------------------------------------------------------
HARNESS="$TMP/harness.sh"
cat >"$HARNESS" <<EOF
#!/usr/bin/env bash
set -uo pipefail
SIDECAR_SETUP_NO_MAIN=1
source "$REPO_ROOT/scripts/setup.sh"
case "\${HARNESS_FN:-verify}" in
    verify) install_verified_sidecar "$REPO" "$TAG" ;;
    legacy) install_legacy_sidecar "$REPO" "$TAG" ;;
    vm)     verify_release_materials "\$VM_DIR" "\$VM_ARCHIVE" \
                "\${VM_REPO:-$REPO}" "\${VM_TAG:-$TAG}" "$COSIGN" "" ;;
esac
EOF
chmod +x "$HARNESS"

stage_materials() { # DISTDIR OUTDIR ARCHIVE
    local d="$2" a="$3"
    rm -rf "$d"; mkdir -p "$d"
    cp "$1/$a" "$1/checksums.txt" "$1/checksums.txt.bundle" \
       "$1/$a.att.bundle" "$1/$a.sbom.cdx.json" "$1/$a.sbom.cdx.json.bundle" "$d/"
}

# ---------------------------------------------------------------------------
section "verifier level: local-key mode, all archives"
for target in $TARGETS; do
    a="sidecar_${VER}_${target}.tar.gz"
    w="$TMP/vm-key-$target"
    stage_materials "$DIST" "$w" "$a"
    out=$(SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" VM_DIR="$w" VM_ARCHIVE="$a" \
        HARNESS_FN=vm bash "$HARNESS" 2>/dev/null); rc=$?
    assert_rc 0 "$rc" "$target verifies"
    [[ "$out" == "$COMMIT" ]] && ok "$target pins commit $COMMIT" \
        || bad "$target commit mismatch: $out"
done

# Repo / tag claim anchors (grep anchors inside the signed statement).
a="sidecar_${VER}_${HOST_TARGET}.tar.gz"
w="$TMP/vm-wrong-repo"; stage_materials "$DIST" "$w" "$a"
if SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" VM_DIR="$w" VM_ARCHIVE="$a" \
        VM_REPO="evil-inc/sidecar" HARNESS_FN=vm bash "$HARNESS" >/dev/null 2>&1; then
    bad "wrong repo name accepted"
else
    ok "wrong repo name rejected"
fi
if SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" VM_DIR="$w" VM_ARCHIVE="$a" \
        VM_TAG="v9.9.9" HARNESS_FN=vm bash "$HARNESS" >/dev/null 2>&1; then
    bad "wrong tag accepted"
else
    ok "wrong tag rejected"
fi

# Single-byte tamper matrix in local-key mode.
section "verifier level: single-byte tamper matrix (local key)"
for target in $TARGETS; do
    a="sidecar_${VER}_${target}.tar.gz"
    for material in "$a" checksums.txt checksums.txt.bundle \
                    "$a.att.bundle" "$a.sbom.cdx.json" "$a.sbom.cdx.json.bundle"; do
        w="$TMP/vm-flip"
        stage_materials "$DIST" "$w" "$a"
        flip_byte "$w/$material"
        if SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" VM_DIR="$w" VM_ARCHIVE="$a" \
                HARNESS_FN=vm bash "$HARNESS" >/dev/null 2>&1; then
            bad "$target / $material tampered but verified"
        else
            ok "$target / $material tamper rejected"
        fi
    done
done

# Provenance commit rewrite with the original signature left stale.
w="$TMP/vm-recommit"; stage_materials "$DIST" "$w" "$a"
python3 "$TMP/mklegacy.py" att "$OPENSSL" "$PKI/leaf.key" "$PKI/leaf.pem" \
    "$DIST/$a.att.bundle" "$w/$a.att.bundle.legacy"
python3 "$TMP/mklegacy.py" recommit "$OPENSSL" "$PKI/leaf.key" "$PKI/leaf.pem" \
    "$w/$a.att.bundle.legacy" "$w/$a.att.bundle"
rm -f "$w/$a.att.bundle.legacy"
if SIDECAR_CERT="$PKI/leaf.pem" SIDECAR_CERT_CHAIN="$PKI/ca.pem" \
        VM_DIR="$w" VM_ARCHIVE="$a" HARNESS_FN=vm bash "$HARNESS" >/dev/null 2>&1; then
    bad "stale-signature commit rewrite accepted"
else
    ok "provenance commit rewrite (stale signature) rejected"
fi

# Attacker-signed bundles must not verify against the victim public key.
section "verifier level: attacker trust root"
for swapped in all att-only; do
    w="$TMP/vm-atk-$swapped"; stage_materials "$DIST" "$w" "$a"
    if [[ "$swapped" == "all" ]]; then
        cp "$ATKDIST/checksums.txt.bundle" "$w/"
        cp "$ATKDIST/$a.att.bundle" "$ATKDIST/$a.sbom.cdx.json.bundle" "$w/"
    else
        cp "$ATKDIST/$a.att.bundle" "$w/"
    fi
    if SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" VM_DIR="$w" VM_ARCHIVE="$a" \
            HARNESS_FN=vm bash "$HARNESS" >/dev/null 2>&1; then
        bad "attacker bundles ($swapped) verified against victim key"
    else
        ok "attacker bundles ($swapped) rejected"
    fi
done

# ---------------------------------------------------------------------------
section "verifier level: certificate identity claims (synthetic CA)"
for target in $TARGETS; do
    a="sidecar_${VER}_${target}.tar.gz"
    w="$TMP/vm-cert-$target"
    stage_materials "$CERTDIST" "$w" "$a"
    out=$(SIDECAR_CERT="$PKI/leaf.pem" SIDECAR_CERT_CHAIN="$PKI/ca.pem" \
        VM_DIR="$w" VM_ARCHIVE="$a" HARNESS_FN=vm bash "$HARNESS" 2>/dev/null); rc=$?
    assert_rc 0 "$rc" "$target verifies with workflow leaf"
    [[ "$out" == "$COMMIT" ]] && ok "$target certificate path pins commit" \
        || bad "$target certificate commit mismatch: $out"
done

for forged in w-identity w-issuer w-trigger w-sha w-workflow w-repo w-ref; do
    w="$TMP/vm-cert-forged"
    stage_materials "$CERTDIST" "$w" "$a"
    if SIDECAR_CERT="$PKI/$forged.pem" SIDECAR_CERT_CHAIN="$PKI/ca.pem" \
            VM_DIR="$w" VM_ARCHIVE="$a" HARNESS_FN=vm bash "$HARNESS" >/dev/null 2>&1; then
        bad "forged leaf $forged accepted"
    else
        ok "forged leaf $forged rejected (identity claim mismatch)"
    fi
done

# Byte tamper over the legacy (certificate) bundles too.
for material in "$a" checksums.txt checksums.txt.bundle \
                "$a.att.bundle" "$a.sbom.cdx.json" "$a.sbom.cdx.json.bundle"; do
    w="$TMP/vm-cert-flip"; stage_materials "$CERTDIST" "$w" "$a"
    flip_byte "$w/$material"
    if SIDECAR_CERT="$PKI/leaf.pem" SIDECAR_CERT_CHAIN="$PKI/ca.pem" \
            VM_DIR="$w" VM_ARCHIVE="$a" HARNESS_FN=vm bash "$HARNESS" >/dev/null 2>&1; then
        bad "cert mode / $material tampered but verified"
    else
        ok "cert mode / $material tamper rejected"
    fi
done

# ---------------------------------------------------------------------------
section "verify-release-trust.sh: four archives, one commit, fully offline"
PROXY_ENV=(HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9
           https_proxy=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9
                           NO_PROXY= NONE_PROXY= no_proxy=)
out=$(env "${PROXY_ENV[@]}" "$REPO_ROOT/scripts/verify-release-trust.sh" \
        "$DIST" "$TAG" "$COMMIT" --key "$KEYDIR/cosign.pub" 2>&1); rc=$?
assert_rc 0 "$rc" "offline trust verification rc"
if grep -q "all 4 assets verify offline to $COMMIT (SBOM main module $TAG)" <<<"$out"; then
    ok "all 4 assets -> same commit, SBOM main module $TAG, zero network"
else
    bad "unexpected trust output: $(tail -1 <<<"$out")"
fi
out=$(env "${PROXY_ENV[@]}" "$REPO_ROOT/scripts/verify-release-trust.sh" \
        "$DIST" "$TAG" "$BAD_SHA" --key "$KEYDIR/cosign.pub" 2>&1); rc=$?
[[ $rc -ne 0 ]] && ok "expected-commit mismatch fails" || bad "commit mismatch accepted"

# ---------------------------------------------------------------------------
# Loopback release server
# ---------------------------------------------------------------------------
section "preparing release HTTP server"
WEB="$TMP/web"
mkdir -p "$WEB/rel/$TAG" "$WEB/cert/$TAG" "$WEB/legacy/$TAG" \
         "$WEB/boot/v3.1.3" "$WEB/badboot/v3.1.3"
cp "$DIST"/* "$WEB/rel/$TAG/"
cp "$CERTDIST"/* "$WEB/cert/$TAG/"
cp "$DIST/sidecar_${VER}_${HOST_TARGET}.tar.gz" "$WEB/legacy/$TAG/"

# Per-tamper docroots, all derived from the pristine release so the server
# never needs restarting between cases.
site_from_rel() { # dir
    rm -rf "$WEB/$1"; mkdir -p "$WEB/$1/$TAG"; cp "$WEB/rel/$TAG/"* "$WEB/$1/$TAG/"
}
for material in archive checksums checksums-bundle att sbom sbom-bundle; do
    site_from_rel "mut-$material"
done
a="sidecar_${VER}_${HOST_TARGET}.tar.gz"
flip_byte "$WEB/mut-archive/$TAG/$a"
flip_byte "$WEB/mut-checksums/$TAG/checksums.txt"
flip_byte "$WEB/mut-checksums-bundle/$TAG/checksums.txt.bundle"
flip_byte "$WEB/mut-att/$TAG/$a.att.bundle"
flip_byte "$WEB/mut-sbom/$TAG/$a.sbom.cdx.json"
flip_byte "$WEB/mut-sbom-bundle/$TAG/$a.sbom.cdx.json.bundle"

# Cert-mode tamper docroots.
for material in archive checksums checksums-bundle att sbom sbom-bundle; do
    rm -rf "$WEB/cmut-$material"; mkdir -p "$WEB/cmut-$material/$TAG"
    cp "$WEB/cert/$TAG/"* "$WEB/cmut-$material/$TAG/"
done
flip_byte "$WEB/cmut-archive/$TAG/$a"
flip_byte "$WEB/cmut-checksums/$TAG/checksums.txt"
flip_byte "$WEB/cmut-checksums-bundle/$TAG/checksums.txt.bundle"
flip_byte "$WEB/cmut-att/$TAG/$a.att.bundle"
flip_byte "$WEB/cmut-sbom/$TAG/$a.sbom.cdx.json"
flip_byte "$WEB/cmut-sbom-bundle/$TAG/$a.sbom.cdx.json.bundle"

# Bootstrap mirrors: serve the OFFICIAL release binary (Homebrew rebuilds
# cosign locally, so a brew-installed cosign has a different hash by design;
# the pinned anchor matches the upstream asset).
OFFICIAL_COSIGN="$TMP/cosign-official-${HOST_OS}-${HOST_ARCH}"
fetch_retry() { # url out
    local i
    for i in 1 2 3 4 5; do
        curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1" && return 0
        sleep $((i * 2))
    done
    return 1
}
fetch_retry \
    "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-${HOST_OS}-${HOST_ARCH}" \
    "$OFFICIAL_COSIGN" || die "could not fetch official cosign v3.1.3 for the bootstrap mirror"
chmod +x "$OFFICIAL_COSIGN"
official_sha=$(sha256_of "$OFFICIAL_COSIGN")
pinned_sha=$(grep -E "^[[:space:]]+${HOST_OS}/${HOST_ARCH}\)" "$REPO_ROOT/scripts/setup.sh" \
    | sed -E 's/.*echo "([0-9a-f]+)".*/\1/')
[[ "$official_sha" == "$pinned_sha" ]] \
    || die "pinned cosign anchor for $HOST_OS/$HOST_ARCH is wrong: $official_sha != $pinned_sha"
cp "$OFFICIAL_COSIGN" "$WEB/boot/v3.1.3/cosign-${HOST_OS}-${HOST_ARCH}"
cp "$OFFICIAL_COSIGN" "$WEB/badboot/v3.1.3/cosign-${HOST_OS}-${HOST_ARCH}"
flip_byte "$WEB/badboot/v3.1.3/cosign-${HOST_OS}-${HOST_ARCH}"
ok "official cosign v3.1.3 ($HOST_OS/$HOST_ARCH) matches the pinned bootstrap anchor"

PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WEB" \
    >"$TMP/httpd.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    curl -sf -o /dev/null "http://127.0.0.1:$PORT/rel/$TAG/checksums.txt" && break
    sleep 0.1
done
curl -sf -o /dev/null "http://127.0.0.1:$PORT/rel/$TAG/checksums.txt" \
    || die "loopback server failed to start"
ok "release server on 127.0.0.1:$PORT"

REL_URL="http://127.0.0.1:$PORT/rel"
CERT_URL="http://127.0.0.1:$PORT/cert"
BOOT_URL="http://127.0.0.1:$PORT/boot"
BADBOOT_URL="http://127.0.0.1:$PORT/badboot"
OFFLINE_PROXY=(HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9
               https_proxy=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9
               NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost)

place_sentinel() { # dir
    mkdir -p "$1"
    printf 'SENTINEL-BINARY-MUST-NOT-MOVE\n' >"$1/sidecar"
}

# e2e SITE_URL MODE(key|cert) EXPECT_RC
# Asserts the return code and, on failure, that the sentinel survives.
e2e() {
    local site="$1" mode="$2" expect="$3" desc="$4"
    local idir="$TMP/e2e-$$-$RANDOM"
    place_sentinel "$idir"
    local before after
    before=$(sha256_of "$idir/sidecar")
    local env_extra=()
    if [[ "$mode" == "key" ]]; then
        env_extra=(SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub")
    else
        env_extra=(SIDECAR_CERT="$PKI/leaf.pem" SIDECAR_CERT_CHAIN="$PKI/ca.pem")
    fi
    env "${OFFLINE_PROXY[@]}" \
        SIDECAR_RELEASE_BASE_URL="$site" \
        SIDECAR_INSTALL_DIR="$idir" \
        SIDECAR_COSIGN_BIN="$COSIGN" \
        "${env_extra[@]}" \
        HARNESS_FN=verify bash "$HARNESS" >"$TMP/e2e.out" 2>&1
    local rc=$?
    after=$(sha256_of "$idir/sidecar")
    if [[ "$rc" == "$expect" ]]; then ok "$desc (rc=$rc)"
    else bad "$desc (wanted rc=$expect, got $rc): $(tail -1 "$TMP/e2e.out")"; fi
    if [[ "$expect" == 0 ]]; then
        if [[ "$before" != "$after" ]] && "$idir/sidecar" | grep -q "$HOST_TARGET"; then
            ok "$desc replaced sentinel with the verified target binary"
        else
            bad "$desc did not install the expected binary"
        fi
    else
        if [[ "$before" == "$after" ]]; then
            ok "$desc left the existing binary byte-for-byte unchanged"
        else
            bad "$desc MODIFIED the existing binary despite failure"
        fi
    fi
}

section "end to end: verified install + atomicity (local key, offline)"
e2e "$REL_URL" key 0 "happy path installs verified sidecar"
e2e "http://127.0.0.1:$PORT/mut-archive" key 11 "archive tampered"
e2e "http://127.0.0.1:$PORT/mut-checksums" key 11 "checksums.txt tampered"
e2e "http://127.0.0.1:$PORT/mut-checksums-bundle" key 11 "checksums signature tampered"
e2e "http://127.0.0.1:$PORT/mut-att" key 11 "provenance attestation tampered"
e2e "http://127.0.0.1:$PORT/mut-sbom" key 11 "SBOM tampered"
e2e "http://127.0.0.1:$PORT/mut-sbom-bundle" key 11 "SBOM signature tampered"
e2e "http://127.0.0.1:$PORT/legacy" key 10 "no provenance => legacy, not installed"
idir="$TMP/e2e-net"; place_sentinel "$idir"
before=$(sha256_of "$idir/sidecar")
env SIDECAR_RELEASE_BASE_URL="http://127.0.0.1:1" \
    SIDECAR_INSTALL_DIR="$idir" SIDECAR_COSIGN_BIN="$COSIGN" \
    SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" \
    HARNESS_FN=verify bash "$HARNESS" >/dev/null 2>&1
rc=$?; after=$(sha256_of "$idir/sidecar")
assert_rc 12 "$rc" "unreachable release service"
[[ "$before" == "$after" ]] && ok "network failure left binary unchanged" \
    || bad "network failure modified the binary"

section "end to end: certificate mode (synthetic CA, offline)"
e2e "$CERT_URL" cert 0 "certificate mode installs verified sidecar"
for m in archive checksums checksums-bundle att sbom sbom-bundle; do
    e2e "http://127.0.0.1:$PORT/cmut-$m" cert 11 "cert mode / $m tampered"
done

section "end to end: cosign bootstrap pinned-hash enforcement"
# Strip PATH so neither cosign nor go is discoverable.
CLEAN_PATH="/usr/bin:/bin"
BOOT_HARNESS="$TMP/boot-harness.sh"
cat >"$BOOT_HARNESS" <<EOF
#!/usr/bin/env bash
set -uo pipefail
SIDECAR_SETUP_NO_MAIN=1
source "$REPO_ROOT/scripts/setup.sh"
install_verified_sidecar "$REPO" "$TAG"
EOF
chmod +x "$BOOT_HARNESS"
idir="$TMP/e2e-boot-ok"; place_sentinel "$idir"
before=$(sha256_of "$idir/sidecar")
env -i PATH="$CLEAN_PATH" HOME="$TMP/home-clean" \
    "${OFFLINE_PROXY[@]}" \
    SIDECAR_RELEASE_BASE_URL="$REL_URL" \
    SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="$BOOT_URL" \
    SIDECAR_INSTALL_DIR="$idir" \
    SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" \
    /bin/bash "$BOOT_HARNESS" >"$TMP/boot-ok.out" 2>&1
rc=$?; after=$(sha256_of "$idir/sidecar")
assert_rc 0 "$rc" "verified install with bootstrapped cosign (no cosign on PATH)"
[[ "$before" != "$after" ]] && ok "bootstrap path installed the binary" \
    || bad "bootstrap path did not install: $(tail -2 "$TMP/boot-ok.out")"

idir="$TMP/e2e-boot-bad"; place_sentinel "$idir"
before=$(sha256_of "$idir/sidecar")
env -i PATH="$CLEAN_PATH" HOME="$TMP/home-clean" \
    "${OFFLINE_PROXY[@]}" \
    SIDECAR_RELEASE_BASE_URL="$REL_URL" \
    SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="$BADBOOT_URL" \
    SIDECAR_INSTALL_DIR="$idir" \
    SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" \
    /bin/bash "$BOOT_HARNESS" >/dev/null 2>&1
rc=$?; after=$(sha256_of "$idir/sidecar")
assert_rc 14 "$rc" "tampered cosign bootstrap refused"
[[ "$before" == "$after" ]] && ok "bad bootstrap left binary unchanged" \
    || bad "bad bootstrap modified the binary"

idir="$TMP/e2e-boot-404"; place_sentinel "$idir"
before=$(sha256_of "$idir/sidecar")
env -i PATH="$CLEAN_PATH" HOME="$TMP/home-clean" \
    "${OFFLINE_PROXY[@]}" \
    SIDECAR_RELEASE_BASE_URL="$REL_URL" \
    SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="http://127.0.0.1:$PORT/missing" \
    SIDECAR_INSTALL_DIR="$idir" \
    SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" \
    /bin/bash "$BOOT_HARNESS" >/dev/null 2>&1
rc=$?; after=$(sha256_of "$idir/sidecar")
assert_rc 14 "$rc" "missing cosign bootstrap refused"
[[ "$before" == "$after" ]] && ok "missing bootstrap left binary unchanged" \
    || bad "missing bootstrap modified the binary"

# ---------------------------------------------------------------------------
section "installer main(): flags, fail-closed behavior"
STUB="$TMP/stub"; mkdir -p "$STUB"
cat >"$STUB/tmux" <<'EOF'
#!/bin/sh
if [ "$1" = "-V" ]; then echo "tmux 3.4"; exit 0; fi
exit 0
EOF
chmod +x "$STUB/tmux"
# Never let the installer try a real Homebrew/apt operation in tests.
printf '#!/bin/sh\nexit 1\n' >"$STUB/brew"; chmod +x "$STUB/brew"
printf '#!/bin/sh\nexit 1\n' >"$STUB/apt-get"; chmod +x "$STUB/apt-get"
printf '#!/bin/sh\nexit 1\n' >"$STUB/sudo"; chmod +x "$STUB/sudo"

run_main() { # site extra-args... ; stdin inherited; output -> $TMP/main.out
    local site="$1"; shift
    env "${OFFLINE_PROXY[@]}" \
        PATH="$STUB:$PATH" HOME="$TMP/home" \
        SIDECAR_RELEASE_BASE_URL="$site" \
        SIDECAR_INSTALL_DIR="$IDIR" \
        SIDECAR_COSIGN_BIN="$COSIGN" \
        SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" \
        /bin/bash "$REPO_ROOT/scripts/setup.sh" \
        --sidecar-only --yes --version "$TAG" "$@" >"$TMP/main.out" 2>&1
}

IDIR="$TMP/main-ok"; place_sentinel "$IDIR"
run_main "$REL_URL"
rc=$?
if grep -q "provenance commit" "$TMP/main.out" && "$IDIR/sidecar" 2>/dev/null | grep -q "$HOST_TARGET"; then
    ok "main: verified install reports provenance commit"
else
    bad "main happy path: $(tail -3 "$TMP/main.out" | tr '\n' ' ')"
fi
grep -qi "brew install" "$TMP/main.out" \
    && bad "main happy path unexpectedly installed deps" \
    || ok "main: no dependency installation prompts on a clean run"

IDIR="$TMP/main-tamper"; place_sentinel "$IDIR"
before=$(sha256_of "$IDIR/sidecar")
run_main "http://127.0.0.1:$PORT/mut-checksums"
after=$(sha256_of "$IDIR/sidecar")
grep -q "FAILED supply-chain verification" "$TMP/main.out" \
    && ok "main: verification failure reported" \
    || bad "main: no verification failure message"
[[ "$before" == "$after" ]] && ok "main: binary untouched after tamper" \
    || bad "main: binary changed after tamper"
grep -q "Building sidecar" "$TMP/main.out" \
    && bad "main: -y implicitly started a source build" \
    || ok "main: -y never falls back to a source build"

IDIR="$TMP/main-legacy"; place_sentinel "$IDIR"
before=$(sha256_of "$IDIR/sidecar")
run_main "http://127.0.0.1:$PORT/legacy"
after=$(sha256_of "$IDIR/sidecar")
grep -q "LEGACY release" "$TMP/main.out" \
    && ok "main: legacy release marked LEGACY" \
    || bad "main: legacy marker missing"
[[ "$before" == "$after" ]] && ok "main: legacy binary not installed by default" \
    || bad "main: legacy binary installed by default"
grep -q "brew install" "$TMP/main.out" \
    && ok "main: legacy guidance points at the Homebrew source formula" \
    || bad "main: legacy Homebrew guidance missing"

IDIR="$TMP/main-legacy-allow"; place_sentinel "$IDIR"
run_main "http://127.0.0.1:$PORT/legacy" --allow-legacy-binary
if grep -q "WITHOUT provenance verification" "$TMP/main.out" \
   && "$IDIR/sidecar" 2>/dev/null | grep -q "$HOST_TARGET"; then
    ok "main: --allow-legacy-binary installs with explicit warning"
else
    bad "main: explicit legacy install failed: $(tail -2 "$TMP/main.out")"
fi

IDIR="$TMP/main-net"; place_sentinel "$IDIR"
before=$(sha256_of "$IDIR/sidecar")
run_main "http://127.0.0.1:1"
after=$(sha256_of "$IDIR/sidecar")
grep -q "could not be downloaded" "$TMP/main.out" \
    && ok "main: unreachable service reports clearly" \
    || bad "main: unreachable-service message missing"
[[ "$before" == "$after" ]] && ok "main: binary untouched when service down" \
    || bad "main: binary changed when service down"
grep -q "Building sidecar" "$TMP/main.out" \
    && bad "main: source build triggered while service unreachable" \
    || ok "main: no unverified/source install while service unreachable"

# Interactive refusal: "n" must mean no source build even with Go present.
IDIR="$TMP/main-no"; place_sentinel "$IDIR"
before=$(sha256_of "$IDIR/sidecar")
printf 'n\n' | env "${OFFLINE_PROXY[@]}" \
    PATH="$STUB:$PATH" HOME="$TMP/home" \
    SIDECAR_RELEASE_BASE_URL="http://127.0.0.1:$PORT/mut-checksums" \
    SIDECAR_INSTALL_DIR="$IDIR" SIDECAR_COSIGN_BIN="$COSIGN" \
    SIDECAR_VERIFY_KEY="$KEYDIR/cosign.pub" \
    /bin/bash "$REPO_ROOT/scripts/setup.sh" --sidecar-only --version "$TAG" \
    >"$TMP/main.out" 2>&1
after=$(sha256_of "$IDIR/sidecar")
[[ "$before" == "$after" ]] && ok "main: interactive 'n' refuses the source build" \
    || bad "main: source build ran after 'n'"

# choose_source_build unit behavior.
SIDECAR_SETUP_NO_MAIN=1 bash -c 'source "'"$REPO_ROOT"'/scripts/setup.sh"; choose_source_build q <<<"n"' \
    >/dev/null 2>&1 || ok "choose_source_build: n => no"
SIDECAR_SETUP_NO_MAIN=1 bash -c 'source "'"$REPO_ROOT"'/scripts/setup.sh"; choose_source_build q' _ --yes \
    >/dev/null 2>&1 || ok "choose_source_build: --yes => no implicit source build"
SIDECAR_SETUP_NO_MAIN=1 bash -c 'source "'"$REPO_ROOT"'/scripts/setup.sh"; choose_source_build q <<<"y"' \
    >/dev/null 2>&1 && ok "choose_source_build: explicit y => yes" \
    || bad "choose_source_build: explicit y not accepted"

# ---------------------------------------------------------------------------
section "embedded trusted root matches the vendored Sigstore root"
rootout="$TMP/trusted_root.json"
TR_OUT="$rootout" SIDECAR_SETUP_NO_MAIN=1 REPO_ROOT="$REPO_ROOT" bash -c '
    source "$REPO_ROOT/scripts/setup.sh"
    write_trusted_root "$TR_OUT"'
if cmp -s "$rootout" "$REPO_ROOT/packaging/sigstore/trusted_root.json"; then
    ok "embedded base64 trusted root is byte-identical to packaging/sigstore/trusted_root.json"
else
    bad "embedded trusted root diverges from the vendored file"
fi
python3 -c 'import json,sys; json.load(open("'"$rootout"'"))' \
    && ok "trusted root is valid JSON" || bad "trusted root is not valid JSON"

# ---------------------------------------------------------------------------
section "syntax: all touched scripts parse"
for s in setup.sh release-attest.sh verify-release-trust.sh test-setup-verification.sh; do
    if /bin/bash -n "$REPO_ROOT/scripts/$s"; then ok "$s parses"
    else bad "$s has a syntax error"; fi
done

# ---------------------------------------------------------------------------
# Clean Linux container: no Go, no cosign, bootstrap + verified install.
# ---------------------------------------------------------------------------
if [[ "${SKIP_DOCKER:-0}" == "1" ]]; then
    note "SKIP_DOCKER=1: clean Linux container section skipped"
else
    section "clean Linux container (no Go, no cosign)"
    IMG="sidecar-verify-clean:native-$HOST_ARCH"
    IMG_AMD64=""
    DKFILE="$TMP/Dockerfile"
    cat >"$DKFILE" <<'EOF'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl python3 bash coreutils gzip tar \
 && rm -rf /var/lib/apt/lists/*
RUN printf '#!/bin/sh\n[ "$1" = "-V" ] && { echo tmux 3.4; exit 0; }\nexit 0\n' \
      > /usr/local/bin/tmux && chmod +x /usr/local/bin/tmux
EOF
    GATEWAY="host.docker.internal"
    docker build -q --platform "linux/$HOST_ARCH" -t "$IMG" -f "$DKFILE" "$TMP" \
        >/dev/null 2>"$TMP/docker-build.log" \
        && ok "clean ubuntu image built (linux/$HOST_ARCH)" \
        || { bad "docker image build failed (see $TMP/docker-build.log)"; IMG=""; }

    if [[ -n "$IMG" && "${SKIP_AMD64:-0}" != "1" && "$HOST_ARCH" != "amd64" ]]; then
        # A platform-specific tag prevents docker from trying to pull this
        # local-only image from a registry under --platform linux/amd64.
        IMG_AMD64="sidecar-verify-clean:amd64"
        if docker build -q --platform linux/amd64 -t "$IMG_AMD64" -f "$DKFILE" "$TMP" \
                >/dev/null 2>"$TMP/docker-build-amd64.log"; then
            ok "clean ubuntu image built (linux/amd64, emulated)"
        else
            bad "linux/amd64 image build failed (see $TMP/docker-build-amd64.log)"
            IMG_AMD64=""
        fi
    fi

    if [[ -n "$IMG" ]]; then
        # Fetch the real linux cosign binaries and check the pinned anchors.
        for arch in arm64 amd64; do
            out="$WEB/boot/v3.1.3/cosign-linux-$arch"
            if [[ ! -s "$out" ]]; then
                fetch_retry \
                    "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$arch" \
                    "$out" || die "could not fetch cosign-linux-$arch"
            fi
            actual=$(sha256_of "$out")
            expected=$(grep -E "^[[:space:]]+linux/$arch\)" "$REPO_ROOT/scripts/setup.sh" \
                | sed -E 's/.*echo "([0-9a-f]+)".*/\1/')
            [[ "$actual" == "$expected" ]] \
                && ok "cosign-linux-$arch pinned anchor verified ($actual)" \
                || bad "cosign-linux-$arch anchor mismatch: $actual != $expected"
        done

        # arm64 native (or amd64 native on Intel)
        native_arch="$HOST_ARCH"
        if docker run --rm --pull never --platform "linux/$native_arch" \
                -v "$REPO_ROOT:/work:ro" -v "$TMP:/fx:ro" \
                -e SIDECAR_RELEASE_BASE_URL="http://$GATEWAY:$PORT/rel" \
                -e SIDECAR_INSTALL_DIR=/out \
                -e SIDECAR_VERIFY_KEY=/fx/keys/cosign.pub \
                -e SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="http://$GATEWAY:$PORT/boot" \
                -e HTTPS_PROXY=http://127.0.0.1:9 -e HTTP_PROXY=http://127.0.0.1:9 \
                -e NO_PROXY="$GATEWAY" \
                "$IMG" sh -c 'bash /work/scripts/setup.sh --sidecar-only --yes --version '"$TAG"' \
                    > /tmp/run.log 2>&1 && /out/sidecar && grep -q "provenance commit" /tmp/run.log' \
                >"$TMP/docker-happy.log" 2>&1; then
            ok "clean linux/$native_arch: verified install via cosign bootstrap, no Go present"
        else
            bad "clean linux/$native_arch happy path failed (see $TMP/docker-happy.log)"
        fi

        log="$TMP/docker-tamper.log"
        docker run --rm --pull never --platform "linux/$native_arch" \
            -v "$REPO_ROOT:/work:ro" -v "$TMP:/fx:ro" \
            -e SIDECAR_RELEASE_BASE_URL="http://$GATEWAY:$PORT/mut-checksums" \
            -e SIDECAR_INSTALL_DIR=/out \
            -e SIDECAR_VERIFY_KEY=/fx/keys/cosign.pub \
            -e SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="http://$GATEWAY:$PORT/boot" \
            -e NO_PROXY="$GATEWAY" \
            "$IMG" sh -c 'echo SENTINEL > /marker; mkdir -p /out; echo SENTINEL > /out/sidecar
                bash /work/scripts/setup.sh --sidecar-only --yes --version '"$TAG"' > /tmp/run.log 2>&1
                rc=0
                grep -q "FAILED supply-chain verification" /tmp/run.log || rc=1
                [ "$(cat /out/sidecar)" = SENTINEL ] || rc=2
                exit $rc' >"$log" 2>&1
        case $? in
            0) ok "clean linux/$native_arch: tamper rejected, sentinel intact" ;;
            1) bad "clean linux: tamper message missing ($log)" ;;
            2) bad "clean linux: tamper installed/modified the binary ($log)" ;;
        esac

        log="$TMP/docker-legacy.log"
        docker run --rm --pull never --platform "linux/$native_arch" \
            -v "$REPO_ROOT:/work:ro" -v "$TMP:/fx:ro" \
            -e SIDECAR_RELEASE_BASE_URL="http://$GATEWAY:$PORT/legacy" \
            -e SIDECAR_INSTALL_DIR=/out \
            -e SIDECAR_VERIFY_KEY=/fx/keys/cosign.pub \
            -e SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="http://$GATEWAY:$PORT/boot" \
            -e NO_PROXY="$GATEWAY" \
            "$IMG" sh -c 'mkdir -p /out; echo SENTINEL > /out/sidecar
                bash /work/scripts/setup.sh --sidecar-only --yes --version '"$TAG"' > /tmp/run.log 2>&1
                grep -q "LEGACY release" /tmp/run.log && [ "$(cat /out/sidecar)" = SENTINEL ]' \
            >"$log" 2>&1 \
            && ok "clean linux/$native_arch: legacy refused by default" \
            || bad "clean linux: legacy behavior wrong ($log)"

        log="$TMP/docker-down.log"
        docker run --rm --pull never --platform "linux/$native_arch" \
            -v "$REPO_ROOT:/work:ro" -v "$TMP:/fx:ro" \
            -e SIDECAR_RELEASE_BASE_URL="http://127.0.0.1:1" \
            -e SIDECAR_INSTALL_DIR=/out \
            -e SIDECAR_VERIFY_KEY=/fx/keys/cosign.pub \
            -e SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="http://$GATEWAY:$PORT/boot" \
            -e NO_PROXY="$GATEWAY" \
            "$IMG" sh -c 'mkdir -p /out; echo SENTINEL > /out/sidecar
                bash /work/scripts/setup.sh --sidecar-only --yes --version '"$TAG"' > /tmp/run.log 2>&1
                grep -q "could not be downloaded" /tmp/run.log && [ "$(cat /out/sidecar)" = SENTINEL ] \
                    && ! grep -q "Building sidecar" /tmp/run.log' \
            >"$log" 2>&1 \
            && ok "clean linux/$native_arch: unreachable service fails closed, no source build" \
            || bad "clean linux: unreachable behavior wrong ($log)"

        if [[ -n "$IMG_AMD64" ]]; then
            log="$TMP/docker-amd64.log"
            docker run --rm --pull never --platform linux/amd64 \
                -v "$REPO_ROOT:/work:ro" -v "$TMP:/fx:ro" \
                -e SIDECAR_RELEASE_BASE_URL="http://$GATEWAY:$PORT/rel" \
                -e SIDECAR_INSTALL_DIR=/out \
                -e SIDECAR_VERIFY_KEY=/fx/keys/cosign.pub \
                -e SIDECAR_COSIGN_BOOTSTRAP_BASE_URL="http://$GATEWAY:$PORT/boot" \
                -e HTTPS_PROXY=http://127.0.0.1:9 -e HTTP_PROXY=http://127.0.0.1:9 \
                -e NO_PROXY="$GATEWAY" \
                "$IMG_AMD64" sh -c 'uname -m | grep -q x86_64
                    bash /work/scripts/setup.sh --sidecar-only --yes --version '"$TAG"' > /tmp/run.log 2>&1
                    /out/sidecar | grep -q linux_amd64
                    grep -q "provenance commit" /tmp/run.log' \
                >"$log" 2>&1 \
                && ok "clean linux/amd64 (emulated): verified install with correct asset" \
                || bad "linux/amd64 pass failed ($log)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
section "Homebrew source-formula publication regression"
# The formula uses Ruby >= 3.1 syntax; prefer Homebrew's portable ruby over
# the ancient system ruby on macOS.
RUBY_BIN=""
for c in "$(brew --repository 2>/dev/null)/Library/Homebrew/vendor/portable-ruby/current/bin/ruby" \
         /opt/homebrew/opt/ruby/bin/ruby /usr/local/opt/ruby/bin/ruby "$(command -v ruby)"; do
    if [[ -x "$c" ]] && "$c" -e 'exit(Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.1") ? 0 : 1)' 2>/dev/null; then
        RUBY_BIN="$c"; break
    fi
done
if [[ -z "$RUBY_BIN" ]]; then
    note "no Ruby >= 3.1 found; skipping publication syntax gate (formula unchanged by this task)"
elif PATH="$(dirname "$RUBY_BIN"):$PATH" "$REPO_ROOT/scripts/test-release-publication.sh" >"$TMP/brew.log" 2>&1; then
    ok "test-release-publication.sh passed with $($RUBY_BIN -e 'print RUBY_VERSION') (formula SHA flow intact)"
else
    bad "test-release-publication.sh failed: $(tail -3 "$TMP/brew.log")"
fi

# ---------------------------------------------------------------------------
printf '\n========================================\n'
if [[ $FAIL -eq 0 ]]; then
    printf '\033[32mALL %d ACCEPTANCE CHECKS PASSED\033[0m\n' "$PASS"
    exit 0
else
    printf '\033[31m%d/%d checks failed:%s\n\033[0m' "$FAIL" "$((PASS+FAIL))" "$FAILED_CASES"
    exit 1
fi
