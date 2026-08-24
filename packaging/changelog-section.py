#!/usr/bin/env python3
"""Print one release's CHANGELOG.md section for the GitHub Release notes.

    changelog-section.py X.Y.Z

Writes the body of the `## [X.Y.Z] - YYYY-MM-DD` section (entries only, no
heading) to stdout, followed by the reference-link definitions the body uses
(CHANGELOG.md keeps those at the bottom of the file, so an extracted section
would otherwise render with dead `[#N]` references). Exits non-zero when the
section is missing or empty, so the release job fails instead of publishing
a release with blank notes.

The version-heading regex is IMPORTED from
packaging/flatpak/gen-metainfo-releases.py — the other consumer of
CHANGELOG.md — so the two can never drift apart in what they accept as a
release heading. Stdlib only, like that script.
"""

import importlib.util
import re
import sys
from pathlib import Path

# Loading gen-metainfo-releases.py below would otherwise drop a __pycache__
# into packaging/flatpak/ on every run — keep the tree clean.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
GENERATOR = ROOT / "packaging" / "flatpak" / "gen-metainfo-releases.py"

# `[label]: url` reference-link definitions (Keep a Changelog puts them at
# the file bottom); matched per line so they can be re-attached to the body.
LINKDEF_RE = re.compile(r"^\[([^\]]+)\]:\s+\S")


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def heading_re():
    # Load HEADING_RE from gen-metainfo-releases.py itself (the hyphenated
    # filename rules out a plain import). Its main() is __main__-guarded, so
    # executing the module only defines constants and functions.
    spec = importlib.util.spec_from_file_location("gen_metainfo_releases", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.HEADING_RE


def section_body(version):
    """The lines of the `## [version]` section: after its heading, up to the
    next version heading (or EOF), trimmed of surrounding blank lines."""
    versions_re = heading_re()
    body = None
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        m = versions_re.match(line)
        if m:
            if body is not None:
                break  # next release heading ends the section
            if m.group(1) == version:
                body = []
            continue
        if body is not None:
            body.append(line)
    if body is None:
        fail(f"no '## [{version}] - YYYY-MM-DD' heading found in {CHANGELOG}")
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    if not body:
        fail(f"the '## [{version}]' section in {CHANGELOG} is empty")
    return body


def used_linkdefs(body):
    """The changelog's link definitions, filtered to labels the body uses."""
    defs = {}
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        m = LINKDEF_RE.match(line)
        if m:
            defs[m.group(1)] = line
    text = "\n".join(body)
    return [line for label, line in defs.items() if f"[{label}]" in text]


def main():
    if len(sys.argv) != 2:
        fail(f"usage: {sys.argv[0]} X.Y.Z")
    version = sys.argv[1]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        fail(f"'{version}' is not a plain X.Y.Z version")
    body = section_body(version)
    links = used_linkdefs(body)
    print("\n".join(body))
    if links:
        print()
        print("\n".join(links))


if __name__ == "__main__":
    main()
