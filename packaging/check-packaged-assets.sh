#!/usr/bin/env bash
#
# Packaged-crate asset check: every file a crate *references* must be a file
# it *ships* in the published .crate tarball.
#
# The incident class: cargo packages only files beneath the package root, so
# a path reaching outside it — `../../packaging/...` — silently vanishes from
# the published crate while still resolving fine in a git checkout. That is
# exactly how the Windows icon broke `cargo install keyroost` before v0.7.7:
# `cargo publish` runs its verification build on Linux where the icon-embedding
# `build.rs` is a no-op, and no workflow builds the packaged tarball at all,
# so the missing asset surfaced only on a user's machine.
#
# What it does, for every workspace crate that uses `include_str!` /
# `include_bytes!` or has a `build.rs`:
#
#   1. Extract every include path (resolved from the referencing source file)
#      and every existing file path a build.rs mentions (string literals that
#      resolve to a real file under the crate root — `assets/keyroost.ico`
#      style).
#   2. A referenced path that escapes the crate root FAILS immediately: cargo
#      cannot package it, no matter what.
#   3. `cargo package -p <crate> --no-verify --offline`, then assert every
#      referenced file is present in the actual tarball listing, naming the
#      missing file and the source line that references it.
#
# Usage:
#   packaging/check-packaged-assets.sh
#
# Entirely offline. Exits non-zero on any missing packaged asset.

set -euo pipefail

cd "$(dirname "$0")/.."

for arg in "$@"; do
  case "$arg" in
    -h|--help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unrecognized argument '$arg'" >&2; exit 2 ;;
  esac
done

python3 - <<'PY'
import os
import re
import subprocess
import sys
import tarfile

FAILS = 0

def fail(msg):
    global FAILS
    FAILS += 1
    print(f"FAIL: {msg}")

# --- collect the referenced-asset inventory per crate -----------------------

INCLUDE_RE = re.compile(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"', re.S)
LITERAL_RE = re.compile(r'"([^"\n]+)"')

crates = sorted(d for d in os.listdir("crates")
                if os.path.isfile(os.path.join("crates", d, "Cargo.toml")))

# crate -> list of (path-relative-to-crate-root, "file.rs:line" reference)
refs = {}

for crate in crates:
    root = os.path.join("crates", crate)
    entries = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "target"]
        for fn in filenames:
            if not fn.endswith(".rs"):
                continue
            src = os.path.join(dirpath, fn)
            txt = open(src, encoding="utf-8").read()
            for m in INCLUDE_RE.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                # include paths resolve relative to the referencing file
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname(src), m.group(1)))
                entries.append((resolved, f"{src}:{line}"))

    build_rs = os.path.join(root, "build.rs")
    if os.path.isfile(build_rs):
        txt = open(build_rs, encoding="utf-8").read()
        entries.append((build_rs, f"{build_rs}:1"))  # build.rs must ship too
        for m in LITERAL_RE.finditer(txt):
            line = txt.count("\n", 0, m.start()) + 1
            lit = m.group(1)
            # cargo:rerun-if-changed=path style — take the path part
            if "=" in lit and lit.startswith("cargo:"):
                lit = lit.split("=", 1)[1]
            # A literal counts as a referenced asset iff it names a real file
            # under the crate root (build.rs paths resolve from there).
            cand = os.path.normpath(os.path.join(root, lit))
            if ("/" in lit or "." in lit) and os.path.isfile(cand):
                entries.append((cand, f"{build_rs}:{line}"))

    if entries:
        # dedupe, keeping the first referencing line
        seen = {}
        for path, where in entries:
            seen.setdefault(path, where)
        refs[crate] = seen

if not refs:
    print("nothing to check: no crate uses include_str!/include_bytes! or build.rs")
    sys.exit(0)

# --- package each crate and diff the tarball against the inventory ----------

for crate in sorted(refs):
    root = os.path.join("crates", crate)
    inventory = refs[crate]
    print(f"== {crate} ({len(inventory)} referenced file(s)) ==")

    # A reference escaping the crate root can never be packaged. Flag it
    # before spending time on cargo.
    escapes = {p: w for p, w in inventory.items()
               if not os.path.abspath(p).startswith(os.path.abspath(root) + os.sep)}
    for p, w in sorted(escapes.items()):
        fail(f"{w}: references {p}, which is OUTSIDE the {crate} package root "
             f"— cargo cannot ship it; move the file under crates/{crate}/")

    r = subprocess.run(
        ["cargo", "package", "-p", crate, "--no-verify", "--offline"],
        capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"cargo package -p {crate} failed:\n{r.stderr.strip()}")
        continue

    m = re.search(r'^version\s*=\s*"([^"]+)"', open("Cargo.toml").read(), re.M)
    version = m.group(1)
    crate_file = os.path.join("target", "package", f"{crate}-{version}.crate")
    if not os.path.isfile(crate_file):
        fail(f"{crate}: expected tarball {crate_file} not found after cargo package")
        continue
    with tarfile.open(crate_file, "r:gz") as tf:
        listing = set(tf.getnames())

    ok = 0
    for path, where in sorted(inventory.items()):
        if path in escapes:
            continue
        rel = os.path.relpath(path, root)
        member = f"{crate}-{version}/{rel}"
        if member in listing:
            ok += 1
        else:
            fail(f"{where}: references {rel}, which is MISSING from "
                 f"{crate_file} — it would vanish from the published crate")
    print(f"  ok: {ok}/{len(inventory)} referenced files present in "
          f"{os.path.basename(crate_file)}")

print()
if FAILS:
    print(f"FAILED — {FAILS} packaged-asset problem(s).", file=sys.stderr)
    sys.exit(1)
print(f"PASS — every referenced file ships in its crate's tarball "
      f"({len(refs)} crate(s) checked).")
PY
