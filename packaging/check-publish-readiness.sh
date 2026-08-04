#!/usr/bin/env bash
#
# Release pre-flight: prove the crates.io fanout can actually run.
#
# Three ways a release-day publish breaks, none of which any other gate
# catches, and all of which are silent until the fanout is already half done:
#
#   1. A crate was added to the workspace since the last release. Trusted
#      Publishing over OIDC cannot CREATE a brand-new crate name, so the very
#      first publish of a new crate must be done by hand, with a crates.io
#      Trusted Publishing entry added afterwards. The fanout job fails on it
#      otherwise — after publishing everything ordered before it.
#   2. A crate exists in the workspace but is missing from publish.yml's list,
#      so it silently never publishes. Downstream users then get a version
#      mismatch on `cargo install`.
#   3. A NEW inter-crate dependency edge was added that publish.yml's order
#      does not respect. cargo refuses to publish a crate whose path-dep
#      sibling is not yet on crates.io at the pinned version, so the run dies
#      partway with half the workspace released and no clean way back.
#
# (3) is the subtle one: every crate can already be published and the release
# still breaks, because what changed is the ORDER requirement, not the set.
# v0.7.7 added keyroost-resolve -> keyroost-openpgp and happened to be ordered
# correctly; nothing would have caught it if it had not been.
#
# Usage:
#   packaging/check-publish-readiness.sh [previous-tag] [--offline]
#
#   previous-tag  Release to diff the member list against.
#                 Defaults to the newest v* tag, which at pre-flight time is
#                 the last release (the new tag does not exist yet).
#   --offline     Skip the crates.io probes; still runs (2) and (3).
#
# Exits non-zero on any problem, with the specific crate named.

set -euo pipefail

cd "$(dirname "$0")/.."

OFFLINE=0
PREV_TAG=""
for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    -h|--help) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         PREV_TAG="$arg" ;;
  esac
done

if [ -z "$PREV_TAG" ]; then
  PREV_TAG=$(git tag --list 'v*' --sort=-v:refname | head -n1)
fi
[ -n "$PREV_TAG" ] || { echo "error: no v* tag found and none given" >&2; exit 2; }

echo "Comparing the workspace against ${PREV_TAG}."
echo

# --- checks 1-3, structural -------------------------------------------------
# python3 does the parsing and writes the member list to stdout for the
# crates.io probe below; findings go to stderr so they are never consumed
# as crate names.
members=$(PREV_TAG="$PREV_TAG" python3 - <<'PY'
import os, re, subprocess, sys

fail = False
def bad(msg):
    global fail
    fail = True
    print(f"FAIL: {msg}", file=sys.stderr)

def members_of(text):
    m = re.search(r'^members\s*=\s*\[(.*?)\]', text, re.S | re.M)
    if not m:
        return []
    return re.findall(r'"crates/([A-Za-z0-9_-]+)"', m.group(1))

cur = members_of(open("Cargo.toml").read())
prev_tag = os.environ["PREV_TAG"]
try:
    prev_txt = subprocess.run(["git", "show", f"{prev_tag}:Cargo.toml"],
                              capture_output=True, text=True, check=True).stdout
    prev = members_of(prev_txt)
except subprocess.CalledProcessError:
    print(f"WARN: cannot read Cargo.toml at {prev_tag}; skipping the members diff",
          file=sys.stderr)
    prev = cur

# 1. crates added since the last release
added = [c for c in cur if c not in prev]
removed = [c for c in prev if c not in cur]
if added:
    print("NEW CRATES since " + prev_tag + ":", file=sys.stderr)
    for c in added:
        print(f"  - {c}", file=sys.stderr)
    print("  Each needs a one-time manual `cargo publish -p <crate>` AND a",
          file=sys.stderr)
    print("  crates.io Trusted Publishing entry (repo framefilter/keyroost,",
          file=sys.stderr)
    print("  workflow publish.yml, environment release-publish) BEFORE the",
          file=sys.stderr)
    print("  release run. OIDC cannot create a crate name.", file=sys.stderr)
    print("  Trusted Publishing config is not machine-checkable here — confirm",
          file=sys.stderr)
    print("  it by hand in the crate's crates.io settings.", file=sys.stderr)
else:
    print(f"ok: no crates added since {prev_tag}", file=sys.stderr)
if removed:
    print("NOTE: crates removed since " + prev_tag + ": " + ", ".join(removed),
          file=sys.stderr)

# 2. publish.yml covers every member
wf = open(".github/workflows/publish.yml").read()
m = re.search(r'for crate in\s+(.*?);\s*do', wf, re.S)
if not m:
    bad("could not find publish.yml's `for crate in ... ; do` list — "
        "the parser needs updating alongside the workflow")
    order = []
else:
    order = m.group(1).replace("\\", " ").split()

missing = [c for c in cur if c not in order]
extra = [c for c in order if c not in cur]
for c in missing:
    bad(f"{c} is a workspace member but is NOT in publish.yml's crate list — "
        f"it would silently never publish")
for c in extra:
    bad(f"publish.yml lists {c}, which is not a workspace member")
if not missing and not extra:
    print(f"ok: publish.yml covers all {len(cur)} members", file=sys.stderr)

# 3. publish order respects every in-tree dependency edge
pos = {c: i for i, c in enumerate(order)}
edges = 0
for c in cur:
    if c not in pos:
        continue
    try:
        txt = open(f"crates/{c}/Cargo.toml").read()
    except OSError:
        continue
    # Path deps only: a `version = "x"` pin without a path is an external
    # crate that happens to share the prefix, and dev-deps on self (the
    # "test with all features" trick) are not publish-order edges.
    for dep in sorted(set(re.findall(
            r'^\s*(keyroost[A-Za-z0-9_-]*)\s*=\s*\{[^}]*path\s*=', txt, re.M))):
        if dep == c:
            continue
        edges += 1
        if dep not in pos:
            bad(f"{c} depends on {dep}, which publish.yml never publishes")
        elif pos[dep] >= pos[c]:
            bad(f"publish ORDER: {c} (#{pos[c]}) depends on {dep} (#{pos[dep]}) "
                f"— the dependency must publish FIRST; move it earlier in "
                f"publish.yml's list")
if not fail:
    print(f"ok: publish order satisfies all {edges} in-tree dependency edges",
          file=sys.stderr)

# member list on stdout for the caller
print("\n".join(cur))
sys.exit(1 if fail else 0)
PY
) || { echo; echo "FAILED — fix the above before tagging." >&2; exit 1; }

# --- crates.io existence probe ----------------------------------------------
echo
if [ "$OFFLINE" = "1" ]; then
  echo "skipped: crates.io probe (--offline)"
else
  # crates.io returns 403 to requests without a User-Agent. Without one, every
  # lookup would read as "missing" and send you hand-publishing crates that
  # already exist.
  UA="keyroost-release (https://github.com/framefilter/keyroost)"
  unpublished=0
  for c in $members; do
    if curl -fsSL -H "User-Agent: ${UA}" \
         "https://crates.io/api/v1/crates/${c}" >/dev/null 2>&1; then
      printf '  %-24s on crates.io\n' "$c"
    else
      printf '  %-24s NOT ON CRATES.IO — needs a manual first publish\n' "$c"
      unpublished=$((unpublished + 1))
    fi
  done
  if [ "$unpublished" -gt 0 ]; then
    echo
    echo "FAILED — ${unpublished} crate(s) cannot be published by the OIDC job." >&2
    exit 1
  fi
fi

echo
echo "PASS — the fanout can publish this workspace."
