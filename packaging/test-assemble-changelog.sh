#!/usr/bin/env bash
#
# Self-test for packaging/assemble-changelog.py. No dependencies beyond
# bash + python3. Builds a throwaway CHANGELOG.md + changelog.d/ in a temp
# directory, runs --check and --release against them, and asserts the
# result — the real repo's CHANGELOG.md and changelog.d/ are never touched.
#
# Usage: packaging/test-assemble-changelog.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/packaging/assemble-changelog.py"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

FAILS=0

fail() {
  echo "FAIL: $1" >&2
  FAILS=$((FAILS + 1))
}

assert_contains() {
  local needle="$1" file="$2" what="$3"
  if ! grep -qF "$needle" "$file"; then
    fail "$what: expected to find $(printf '%q' "$needle") in $file"
  fi
}

assert_order() {
  # asserts $1 appears before $2 in $3
  local first="$1" second="$2" file="$3"
  local l1 l2
  l1="$(grep -nF "$first" "$file" | head -1 | cut -d: -f1)"
  l2="$(grep -nF "$second" "$file" | head -1 | cut -d: -f1)"
  if [ -z "$l1" ] || [ -z "$l2" ] || [ "$l1" -ge "$l2" ]; then
    fail "expected '$first' (line ${l1:-?}) before '$second' (line ${l2:-?}) in $file"
  fi
}

mkdir -p "$TMPDIR/changelog.d"

cat > "$TMPDIR/CHANGELOG.md" <<'EOF'
# Changelog

All notable changes to keyroost are documented here.

## [Unreleased]

## [1.2.0] - 2025-12-01

### Added
- **Something old.** Already shipped. ([#5])

[#5]: https://github.com/framefilter/keyroost/issues/5
[Unreleased]: https://github.com/framefilter/keyroost/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/framefilter/keyroost/releases/tag/v1.2.0
EOF

# Two fragments, deliberately created out of ref order, in two different
# sections, to prove ordering (by ref ascending) and section grouping
# (fixed order Added/Changed/.../Security) both hold. #20's ref also
# already has a link definition (added below) to prove no-duplication.
cat > "$TMPDIR/changelog.d/added-20-second-thing.md" <<'EOF'
- **Second thing.** Added later but has the higher PR number. ([#20])
EOF

cat > "$TMPDIR/changelog.d/fixed-10-first-bug.md" <<'EOF'
- **First bug.** Fixed a thing that was broken. ([#10])
EOF

echo "== running --check on a valid pair of fragments ==" >&2
(
  cd "$TMPDIR"
  python3 "$SCRIPT" --check
) || fail "--check on valid fragments exited non-zero"

echo "== running --check on an empty changelog.d/ ==" >&2
EMPTY="$TMPDIR/empty"
mkdir -p "$EMPTY/changelog.d"
out="$(cd "$EMPTY" && python3 "$SCRIPT" --check)" || fail "--check on empty dir exited non-zero"
case "$out" in
  *"no fragments"*) ;;
  *) fail "--check on empty dir did not mention 'no fragments' (got: $out)" ;;
esac

echo "== running --check on a broken fragment (bad filename) ==" >&2
mkdir -p "$TMPDIR/broken/changelog.d"
echo '- broken, no ref' > "$TMPDIR/broken/changelog.d/not-a-valid-name.md"
if (cd "$TMPDIR/broken" && python3 "$SCRIPT" --check) >/dev/null 2>&1; then
  fail "--check on a bad filename should have failed"
fi

echo "== running --check on a fragment with no credit ref ==" >&2
mkdir -p "$TMPDIR/noref/changelog.d"
echo '- **No credit.** Missing the reference.' > "$TMPDIR/noref/changelog.d/added-1-no-ref.md"
if (cd "$TMPDIR/noref" && python3 "$SCRIPT" --check) >/dev/null 2>&1; then
  fail "--check on a fragment with no ([#N]) should have failed"
fi

echo "== running --check on a fragment with an overlong line ==" >&2
mkdir -p "$TMPDIR/longline/changelog.d"
python3 -c "print('- **Long.** ' + ('x' * 90) + ' ([#1])')" \
  > "$TMPDIR/longline/changelog.d/added-1-long.md"
if (cd "$TMPDIR/longline" && python3 "$SCRIPT" --check) >/dev/null 2>&1; then
  fail "--check on an overlong line should have failed"
fi

echo "== running --release 9.9.9 --date 2026-01-01 ==" >&2
(
  cd "$TMPDIR"
  python3 "$SCRIPT" --release 9.9.9 --date 2026-01-01
) || fail "--release exited non-zero"

CL="$TMPDIR/CHANGELOG.md"

assert_contains "## [Unreleased]" "$CL" "Unreleased heading kept"
assert_contains "## [9.9.9] - 2026-01-01" "$CL" "new version heading byte-format"
assert_order "## [Unreleased]" "## [9.9.9] - 2026-01-01" "$CL"
assert_order "## [9.9.9] - 2026-01-01" "## [1.2.0] - 2025-12-01" "$CL"

# section order: Added before Fixed, even though the Fixed fragment (#10)
# has a lower ref than the Added fragment (#20) — section order wins.
assert_order "### Added" "### Fixed" "$CL"
assert_contains "**Second thing.**" "$CL" "added fragment body present"
assert_contains "**First bug.**" "$CL" "fixed fragment body present"

# fragments within a section ordered by ref ascending — only one fragment
# per section here, but assert the whole line rendered with its ref intact.
assert_contains "([#20])" "$CL" "added fragment credit ref"
assert_contains "([#10])" "$CL" "fixed fragment credit ref"

# link plumbing: new ref gets a definition, existing one is not duplicated.
assert_contains "[#10]: https://github.com/framefilter/keyroost/issues/10" "$CL" "new #10 link def"
assert_contains "[#20]: https://github.com/framefilter/keyroost/issues/20" "$CL" "new #20 link def"
if [ "$(grep -c '^\[#5\]:' "$CL")" != "1" ]; then
  fail "existing [#5] link definition was duplicated or lost"
fi

# compare-chain links.
assert_contains "[9.9.9]: https://github.com/framefilter/keyroost/compare/v1.2.0...v9.9.9" "$CL" "new version compare link"
assert_contains "[Unreleased]: https://github.com/framefilter/keyroost/compare/v9.9.9...HEAD" "$CL" "repointed Unreleased link"

# fragments consumed.
if [ -e "$TMPDIR/changelog.d/added-20-second-thing.md" ]; then
  fail "consumed fragment added-20-second-thing.md was not deleted"
fi
if [ -e "$TMPDIR/changelog.d/fixed-10-first-bug.md" ]; then
  fail "consumed fragment fixed-10-first-bug.md was not deleted"
fi
if [ -n "$(ls -A "$TMPDIR/changelog.d" 2>/dev/null)" ]; then
  fail "changelog.d/ should be empty after --release, found: $(ls -A "$TMPDIR/changelog.d")"
fi

echo "== running --check after --release (fragments gone) ==" >&2
out="$(cd "$TMPDIR" && python3 "$SCRIPT" --check)" || fail "--check after release exited non-zero"
case "$out" in
  *"no fragments"*) ;;
  *) fail "--check after release did not report 'no fragments' (got: $out)" ;;
esac

echo
if [ "$FAILS" -gt 0 ]; then
  echo "FAILED — $FAILS assertion(s) failed." >&2
  exit 1
fi
echo "PASS — assemble-changelog.py self-test clean."
