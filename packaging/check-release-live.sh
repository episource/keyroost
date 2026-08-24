#!/usr/bin/env bash
#
# Post-release channel verification: prove every fanout channel actually
# SERVES the release, not just that its publish job went green.
#
# The incident classes this exists to catch, each of which has bitten or
# nearly bitten a real release:
#
#   1. A green publish job that was a no-op — the job succeeded but the
#      channel still serves the previous version (missing PAT, frozen AUR,
#      a formula push that didn't land). "The workflow passed" proves the
#      workflow ran, not that users can install the release.
#   2. A Release with a missing asset — the linux-bundles attach step lost
#      its race window (v0.7.6 lost a 2-minute window by 16 seconds) and the
#      AppImage/flatpak never made it onto the Release.
#   3. winget shipped from an UNSIGNED zip — the winget manifest must point
#      at the Token2-signed asset, so an absent winget version while the
#      signed zip is also absent is the DESIGNED holding state, not a bug.
#      Absent while the signed zip IS attached means the re-dispatch was
#      forgotten.
#
# Every channel gets an explicit verdict line: LIVE / STALE / HOLDING /
# PR-OPEN / ABSENT-YET.
#
# Usage:
#   packaging/check-release-live.sh <vX.Y.Z> [--wait-aur]
#
#   vX.Y.Z      The release tag to verify (with the leading v).
#   --wait-aur  AUR's RPC lags pushes by minutes; by default a stale AUR is
#               a WARN. With this flag the script polls the RPC (30s apart,
#               up to 10 minutes) and a still-stale AUR becomes a FAIL.
#
# Needs: gh (authenticated), curl, python3. Network is the whole point;
# there is no --offline mode.
#
# Exits non-zero if any non-WARN check fails.

set -euo pipefail

cd "$(dirname "$0")/.."

TAG=""
WAIT_AUR=0
for arg in "$@"; do
  case "$arg" in
    --wait-aur) WAIT_AUR=1 ;;
    -h|--help)  sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    v*)         TAG="$arg" ;;
    *)          echo "error: unrecognized argument '$arg' (tag must start with v)" >&2; exit 2 ;;
  esac
done
[ -n "$TAG" ] || { echo "usage: $0 <vX.Y.Z> [--wait-aur]" >&2; exit 2; }
case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "error: '$TAG' does not look like vX.Y.Z" >&2; exit 2 ;;
esac
VER="${TAG#v}"

# crates.io returns 403 to requests without a User-Agent (see
# check-publish-readiness.sh); use one everywhere for consistency.
UA="keyroost-release (https://github.com/framefilter/keyroost)"

FAILS=0
WARNS=0
fail() { FAILS=$((FAILS + 1)); echo "FAIL: $*"; }
warn() { WARNS=$((WARNS + 1)); echo "WARN: $*"; }

echo "Verifying release channels for ${TAG}."

# --- (a) GitHub release assets ----------------------------------------------
echo
echo "== GitHub release assets =="
assets=$(gh release view "$TAG" --json assets --jq '.assets[].name' 2>/dev/null) \
  || { fail "gh release view ${TAG} failed — no such release?"; assets=""; }

expected=(
  "keyroost-${TAG}-linux-x86_64.tar.gz"
  "keyroost-${TAG}-macos-universal2.tar.gz"
  "keyroost-${TAG}-windows-x86_64.zip"
  "SHA256SUMS"
  "keyroost-x86_64.AppImage"
  "keyroost-x86_64.AppImage.sha256"
  "keyroost-x86_64.AppImage.zsync"
  "keyroost.flatpak"
  "keyroost.flatpak.sha256"
)
missing=0
for a in "${expected[@]}"; do
  if grep -qxF "$a" <<<"$assets"; then
    printf '  present: %s\n' "$a"
  else
    fail "release asset MISSING: $a"
    missing=1
  fi
done
if [ "$missing" = "0" ] && [ -n "$assets" ]; then
  echo "verdict: GitHub release LIVE (all ${#expected[@]} required assets)"
fi

# Signed assets arrive later from the vendor; absence is a state, not an error.
SIGNED_ZIP="keyroost-${TAG}-windows-x86_64-signed.zip"
SIGNED_PKG="keyroost-${TAG}-macos-universal2-signed.pkg"
HAVE_SIGNED_ZIP=0
for s in "$SIGNED_ZIP" "$SIGNED_PKG"; do
  if grep -qxF "$s" <<<"$assets"; then
    printf '  signed asset present: %s\n' "$s"
    [ "$s" = "$SIGNED_ZIP" ] && HAVE_SIGNED_ZIP=1
  else
    printf '  signed asset absent-yet: %s (vendor signing is asynchronous)\n' "$s"
  fi
done

# --- (b) crates.io ----------------------------------------------------------
echo
echo "== crates.io =="
for c in keyroostctl keyroost; do
  body=$(curl -fsSL -H "User-Agent: ${UA}" \
    "https://crates.io/api/v1/crates/${c}/${VER}" 2>/dev/null) || body=""
  if [ -z "$body" ]; then
    fail "crates.io: ${c} ${VER} NOT FOUND — verdict: STALE"
  elif grep -q '"yanked":true' <<<"$body"; then
    fail "crates.io: ${c} ${VER} exists but is YANKED"
  else
    echo "verdict: crates.io ${c} ${VER} LIVE"
  fi
done

# --- (c) Homebrew tap -------------------------------------------------------
echo
echo "== Homebrew (framefilter/homebrew-keyroost) =="
brew_ver=$(curl -fsSL \
  "https://raw.githubusercontent.com/framefilter/homebrew-keyroost/main/Formula/keyroost.rb" \
  2>/dev/null | sed -n 's/^ *version "\([^"]*\)".*/\1/p' | head -n1) || brew_ver=""
if [ -z "$brew_ver" ]; then
  fail "Homebrew: could not read Formula/keyroost.rb from the tap"
elif [ "$brew_ver" = "$VER" ]; then
  echo "verdict: Homebrew formula LIVE (version ${brew_ver})"
else
  fail "Homebrew formula STALE: serves ${brew_ver}, expected ${VER}"
fi

# --- (d) AUR ----------------------------------------------------------------
echo
echo "== AUR (keyroost-bin) =="
echo "note: the AUR RPC lags pushes by minutes — a just-published release can"
echo "      legitimately read stale here for a little while."
aur_probe() {
  curl -fsSL -H "User-Agent: ${UA}" \
    "https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=keyroost-bin" 2>/dev/null \
    | python3 -c 'import json,sys
d = json.load(sys.stdin)
r = d.get("results") or []
print(r[0]["Version"] if r else "")'
}
aur_full=$(aur_probe || true)
aur_ver="${aur_full%%-*}"
if [ "$aur_ver" = "$VER" ]; then
  echo "verdict: AUR keyroost-bin LIVE (${aur_full})"
elif [ "$WAIT_AUR" = "1" ]; then
  echo "AUR serves ${aur_full:-nothing}; polling up to 10 minutes (--wait-aur)…"
  deadline=$((SECONDS + 600))
  while [ "$aur_ver" != "$VER" ] && [ "$SECONDS" -lt "$deadline" ]; do
    sleep 30
    aur_full=$(aur_probe || true)
    aur_ver="${aur_full%%-*}"
  done
  if [ "$aur_ver" = "$VER" ]; then
    echo "verdict: AUR keyroost-bin LIVE (${aur_full})"
  else
    fail "AUR keyroost-bin STALE after 10 min: serves ${aur_full:-nothing}, expected ${VER}"
  fi
else
  warn "AUR keyroost-bin serves ${aur_full:-nothing}, expected ${VER} — verdict: STALE (RPC lag? re-run with --wait-aur to enforce)"
fi

# --- (e) Flatpak OSTree repo ------------------------------------------------
# The repo at framefilter.github.io/keyroost-flatpak is a bare OSTree archive:
# there is no plain appstream.xml URL, but everything needed to reach it IS
# plain-HTTPS-fetchable: ref -> commit object -> root dirtree -> the
# appstream.xml.gz content object (archive-z2: raw-DEFLATE around the gzip).
# Walking that chain needs no configured flatpak remote and no ostree binary.
echo
echo "== Flatpak (framefilter.github.io/keyroost-flatpak) =="
flatpak_out=$(python3 - "$VER" <<'PY'
import re, struct, sys, urllib.request, zlib, gzip

BASE = "https://framefilter.github.io/keyroost-flatpak"
UA = "keyroost-release (https://github.com/framefilter/keyroost)"
want = sys.argv[1]

def fetch(path):
    req = urllib.request.Request(f"{BASE}/{path}", headers={"User-Agent": UA})
    return urllib.request.urlopen(req, timeout=30).read()

def die(msg):
    print(f"FAIL: flatpak: {msg}")
    sys.exit(1)

# The app ref must exist at all — a repo that lost its ref serves nothing.
try:
    app_ref = "refs/heads/app/io.github.framefilter.keyroost/x86_64/master"
    fetch(app_ref)
    print(f"  app ref present: {app_ref}")
except Exception as e:
    die(f"app ref missing ({e})")

try:
    commit_hex = fetch("refs/heads/appstream/x86_64").decode().strip()
    commit = fetch(f"objects/{commit_hex[:2]}/{commit_hex[2:]}.commit")
except Exception as e:
    die(f"cannot fetch appstream ref/commit ({e})")

# The ostree commit GVariant ends with [root-contents csum (32)][root-meta
# csum (32)][framing offsets]. The framing-offset region's width varies, so
# probe backwards for the 32 bytes that name a fetchable .dirtree object —
# self-validating, and robust against commit-metadata size changes.
dirtree = None
for off in range(0, 33):
    cand = commit[len(commit) - off - 64 : len(commit) - off - 32]
    if len(cand) != 32:
        continue
    h = cand.hex()
    try:
        dirtree = fetch(f"objects/{h[:2]}/{h[2:]}.dirtree")
        break
    except Exception:
        continue
if dirtree is None:
    die("could not locate the appstream root dirtree (repo layout changed?)")

i = dirtree.find(b"appstream.xml.gz\x00")
if i < 0:
    die("appstream.xml.gz not present in the appstream branch")
csum = dirtree[i + len(b"appstream.xml.gz\x00") : i + len(b"appstream.xml.gz\x00") + 32].hex()
try:
    filez = fetch(f"objects/{csum[:2]}/{csum[2:]}.filez")
except Exception as e:
    die(f"cannot fetch appstream content object ({e})")

# archive-z2 .filez = GVariant header + raw DEFLATE of the content. Scan for
# the deflate start rather than parsing the header variant.
data = None
for start in range(4, min(len(filez), 256)):
    try:
        d = zlib.decompress(filez[start:], -15)
        if len(d) > 64:
            data = d
            break
    except Exception:
        pass
if data is None:
    j = filez.find(b"\x1f\x8b\x08")
    if j < 0:
        die("could not decompress the appstream content object")
    data = filez[j:]
xml = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
versions = re.findall(r'<release[^>]*version="([^"]+)"', xml.decode("utf-8", "replace"))
if not versions:
    die("appstream XML carries no <release> entries")
newest = versions[0]
print(f"  appstream newest release: {newest} (total {len(versions)} entries)")
if newest == want:
    print(f"verdict: Flatpak repo LIVE ({want} is the newest appstream release)")
else:
    print(f"FAIL: Flatpak repo STALE: newest appstream release is {newest}, expected {want}")
    sys.exit(1)
PY
) || fail "flatpak channel check failed"
echo "$flatpak_out"

# --- (f) winget --------------------------------------------------------------
echo
echo "== winget (microsoft/winget-pkgs) =="
if gh api "repos/microsoft/winget-pkgs/contents/manifests/f/Framefilter/Keyroost/${VER}" \
     --jq '.[].name' >/dev/null 2>&1; then
  echo "verdict: winget Framefilter.Keyroost ${VER} LIVE"
else
  pr=$(gh api -X GET search/issues \
        -f q="repo:microsoft/winget-pkgs is:pr Framefilter.Keyroost ${VER}" \
        --jq '[.items[] | select(.state == "open")][0].html_url' 2>/dev/null) || pr=""
  if [ -n "$pr" ] && [ "$pr" != "null" ]; then
    echo "verdict: winget ${VER} PR-OPEN — ${pr} (waiting on winget-pkgs review)"
  elif [ "$HAVE_SIGNED_ZIP" = "0" ]; then
    echo "verdict: winget ${VER} HOLDING — no manifest AND no signed zip attached."
    echo "  This is the designed state: winget waits for the Token2-signed zip."
    echo "  When the signed zip lands, re-dispatch publish.yml to open the PR."
  else
    fail "winget ${VER} ABSENT although the signed zip IS attached — the publish.yml re-dispatch was likely forgotten"
  fi
fi

# --- verdict -----------------------------------------------------------------
echo
if [ "$FAILS" -gt 0 ]; then
  echo "FAILED — ${FAILS} channel check(s) failed, ${WARNS} warning(s)." >&2
  exit 1
fi
if [ "$WARNS" -gt 0 ]; then
  echo "PASS with ${WARNS} warning(s) — every non-WARN channel serves ${TAG}."
else
  echo "PASS — every channel serves ${TAG}."
fi
