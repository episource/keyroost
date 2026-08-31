#!/usr/bin/env python3
"""Validate and assemble changelog.d/ fragments into CHANGELOG.md.

Every PR used to edit the top of CHANGELOG.md's `[Unreleased]` section
directly, so any two concurrent branches touching the changelog conflicted.
Now a PR drops one small file into `changelog.d/` instead, and this script
assembles them at release time. Stdlib only. Run from the repository root
(paths below are relative to the current working directory, matching the
other scripts in packaging/).

    packaging/assemble-changelog.py --check
        Validates every fragment currently in changelog.d/. Exits non-zero
        with one message per violation. Exits 0 (with a "no fragments"
        note) when the directory holds no fragments.

    packaging/assemble-changelog.py --release X.Y.Z [--date YYYY-MM-DD]
        Assembles every fragment into a new `## [X.Y.Z] - DATE` section
        inserted directly under the `## [Unreleased]` heading, adds any
        missing `[#N]` link definitions and the version's compare link,
        repoints `[Unreleased]` at the new version, and deletes the
        fragments it consumed. Refuses to run (no changes written) if any
        fragment fails validation.

Fragment filenames: `<section>-<ref>-<slug>.md`, where `<section>` is one
of added/changed/fixed/deprecated/removed/security, `<ref>` is the PR or
issue number, and `<slug>` is a short kebab-case description — for example
`added-116-generate-key-convenience.md`. A fragment's content is exactly
the bullet(s) to add, in CHANGELOG.md's house style (`- **Bold lead.** …`,
two-space continuation indents, ending with a `([#N])` credit reference).
No frontmatter.
"""

import argparse
import datetime
import re
import sys
from pathlib import Path

REPO_ISSUE_URL = "https://github.com/framefilter/keyroost/issues/{n}"
REPO_COMPARE_URL = "https://github.com/framefilter/keyroost/compare/v{a}...v{b}"
REPO_COMPARE_HEAD_URL = "https://github.com/framefilter/keyroost/compare/v{a}...HEAD"

# Fixed section order the assembled release follows; the key is the
# filename's <section> token, the value the CHANGELOG subsection heading.
SECTION_ORDER = [
    ("added", "Added"),
    ("changed", "Changed"),
    ("fixed", "Fixed"),
    ("deprecated", "Deprecated"),
    ("removed", "Removed"),
    ("security", "Security"),
]

FRAGMENT_RE = re.compile(
    r"^(added|changed|fixed|deprecated|removed|security)-(\d+)-"
    r"([a-z0-9]+(?:-[a-z0-9]+)*)\.md$"
)
CREDIT_RE = re.compile(r"\(\[#\d+\]")
REF_RE = re.compile(r"\[#(\d+)\]")
MAX_LINE_LEN = 80


def fail_exit(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def find_fragments(changelog_dir):
    if not changelog_dir.is_dir():
        return []
    return sorted(p for p in changelog_dir.iterdir() if p.suffix == ".md")


def validate_fragment(path):
    """Return (fails, warns) — lists of human-readable messages."""
    fails = []
    warns = []
    name = path.name
    m = FRAGMENT_RE.match(name)
    if not m:
        fails.append(
            f"{name}: filename must match '<section>-<ref>-<slug>.md' "
            f"(section one of added/changed/fixed/deprecated/removed/security, "
            f"ref digits, slug kebab-case)"
        )
    ref = m.group(2) if m else None

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        fails.append(f"{name}: cannot read file ({e})")
        return fails, warns

    if not content.strip():
        fails.append(f"{name}: fragment is empty")
        return fails, warns

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LEN:
            fails.append(
                f"{name}:{lineno}: line is {len(line)} chars, "
                f"longer than {MAX_LINE_LEN}"
            )

    if not lines[0].startswith("- "):
        fails.append(
            f"{name}: body must start with '- ' (no frontmatter — the "
            f"first line is the bullet itself)"
        )

    if not CREDIT_RE.search(content):
        fails.append(f"{name}: no '([#N])' credit reference found in the body")
    elif ref is not None:
        refs = {int(n) for n in REF_RE.findall(content)}
        if int(ref) not in refs:
            warns.append(
                f"{name}: filename ref #{ref} does not match any "
                f"'([#N])' reference in the body (found {sorted(refs)})"
            )

    return fails, warns


def cmd_check(changelog_dir):
    fragments = find_fragments(changelog_dir)
    if not fragments:
        print(f"no fragments in {changelog_dir}/ — OK")
        return 0

    all_fails = []
    all_warns = []
    for path in fragments:
        fails, warns = validate_fragment(path)
        all_fails.extend(fails)
        all_warns.extend(warns)

    for w in all_warns:
        print(f"WARN: {w}")
    for f in all_fails:
        print(f"FAIL: {f}")

    if all_fails:
        print(
            f"{len(all_fails)} problem(s) across {len(fragments)} fragment(s).",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(fragments)} fragment(s) valid ({len(all_warns)} warning(s)).")
    return 0


def build_section_body(parsed):
    """parsed: list of (section_key, ref, path). Returns the assembled
    body text (no leading/trailing blank lines) in fixed section order,
    fragments within a section ordered by ref ascending."""
    grouped = {}
    for section, ref, path in parsed:
        grouped.setdefault(section, []).append((ref, path))
    for items in grouped.values():
        items.sort(key=lambda t: (t[0], t[1].name))

    blocks = []
    for key, title in SECTION_ORDER:
        items = grouped.get(key)
        if not items:
            continue
        block_lines = [f"### {title}"]
        for _ref, path in items:
            text = path.read_text(encoding="utf-8").rstrip("\n")
            block_lines.extend(text.split("\n"))
        blocks.append("\n".join(block_lines))
    return "\n\n".join(blocks)


def ensure_issue_defs(changelog_text, refs):
    """Add any missing `[#N]: .../issues/N` link definitions. Existing
    definitions (pointing at /issues/ or /pull/ — GitHub redirects either
    way) are never duplicated or touched."""
    existing = {int(n) for n in re.findall(r"^\[#(\d+)\]:", changelog_text, flags=re.M)}
    missing = sorted(r for r in refs if r not in existing)
    if not missing:
        return changelog_text

    out_lines = changelog_text.split("\n")
    for r in missing:
        new_def = f"[#{r}]: {REPO_ISSUE_URL.format(n=r)}"
        insert_at = None
        for i, line in enumerate(out_lines):
            m = re.match(r"^\[#(\d+)\]:", line)
            if m and int(m.group(1)) > r:
                insert_at = i
                break
        if insert_at is None:
            for i, line in enumerate(out_lines):
                if re.match(r"^\[Unreleased\]:", line):
                    insert_at = i
                    break
        if insert_at is None:
            insert_at = len(out_lines)
        out_lines.insert(insert_at, new_def)
    return "\n".join(out_lines)


def update_version_links(changelog_text, version):
    """Repoint [Unreleased] at the new version and add the new version's
    own compare link, deriving <prev> from [Unreleased]'s current link."""
    m = re.search(r"^\[Unreleased\]:\s*(\S+)\s*$", changelog_text, flags=re.M)
    if not m:
        fail_exit("CHANGELOG.md has no '[Unreleased]:' link definition")
    old_url = m.group(1)

    pm = re.search(r"/compare/v([\d.]+)\.\.\.HEAD$", old_url)
    if not pm:
        fail_exit(f"could not parse a previous version out of '[Unreleased]: {old_url}'")
    prev_version = pm.group(1)

    new_unreleased_url = REPO_COMPARE_HEAD_URL.format(a=version)
    changelog_text = re.sub(
        r"^\[Unreleased\]:\s*\S+\s*$",
        lambda _m: f"[Unreleased]: {new_unreleased_url}",
        changelog_text,
        count=1,
        flags=re.M,
    )

    new_version_def = f"[{version}]: {REPO_COMPARE_URL.format(a=prev_version, b=version)}"
    changelog_text = re.sub(
        r"^(\[Unreleased\]:.*)$",
        lambda m2: m2.group(1) + "\n" + new_version_def,
        changelog_text,
        count=1,
        flags=re.M,
    )
    return changelog_text


def cmd_release(version, date, changelog_path, changelog_dir):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        fail_exit(f"version '{version}' must look like X.Y.Z")

    fragments = find_fragments(changelog_dir)
    if not fragments:
        fail_exit(f"no fragments in {changelog_dir}/ — nothing to assemble")

    all_fails = []
    parsed = []
    for path in fragments:
        fails, warns = validate_fragment(path)
        all_fails.extend(fails)
        for w in warns:
            print(f"WARN: {w}")
        m = FRAGMENT_RE.match(path.name)
        if m:
            parsed.append((m.group(1), int(m.group(2)), path))

    if all_fails:
        for f in all_fails:
            print(f"FAIL: {f}", file=sys.stderr)
        fail_exit(
            f"{len(all_fails)} problem(s) in changelog.d/ — fix them before "
            f"assembling a release"
        )

    section_body = build_section_body(parsed)
    all_refs = sorted({int(n) for n in REF_RE.findall(section_body)})

    if not changelog_path.is_file():
        fail_exit(f"{changelog_path} does not exist")
    changelog_text = changelog_path.read_text(encoding="utf-8")
    lines = changelog_text.split("\n")

    idx = next(
        (i for i, line in enumerate(lines) if re.match(r"^## \[Unreleased\]\s*$", line)),
        None,
    )
    if idx is None:
        fail_exit(f"{changelog_path} has no '## [Unreleased]' heading")

    heading_line = f"## [{version}] - {date}"
    new_block = [""] + [heading_line, ""] + section_body.split("\n")
    lines = lines[: idx + 1] + new_block + lines[idx + 1 :]
    changelog_text = "\n".join(lines)

    changelog_text = ensure_issue_defs(changelog_text, all_refs)
    changelog_text = update_version_links(changelog_text, version)

    changelog_path.write_text(changelog_text, encoding="utf-8")

    for _section, _ref, path in parsed:
        path.unlink()

    print(
        f"assembled {len(parsed)} fragment(s) into '## [{version}] - {date}' "
        f"in {changelog_path}; consumed fragment(s) removed from {changelog_dir}/."
    )
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Validate and assemble changelog.d/ fragments into CHANGELOG.md.",
    )
    parser.add_argument(
        "--check", action="store_true", help="validate every fragment in changelog.d/"
    )
    parser.add_argument(
        "--release", metavar="X.Y.Z", help="assemble fragments into a new release section"
    )
    parser.add_argument(
        "--date",
        metavar="YYYY-MM-DD",
        help="release date for --release (default: today)",
    )
    parser.add_argument(
        "--changelog",
        metavar="PATH",
        default="CHANGELOG.md",
        help="path to CHANGELOG.md (default: ./CHANGELOG.md)",
    )
    parser.add_argument(
        "--fragments-dir",
        metavar="PATH",
        default="changelog.d",
        help="path to the fragments directory (default: ./changelog.d)",
    )
    args = parser.parse_args()

    if bool(args.check) == bool(args.release):
        parser.error("pass exactly one of --check or --release X.Y.Z")

    changelog_dir = Path(args.fragments_dir)

    if args.check:
        sys.exit(cmd_check(changelog_dir))

    date = args.date or datetime.date.today().isoformat()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        fail_exit(f"--date '{date}' must look like YYYY-MM-DD")

    sys.exit(cmd_release(args.release, date, Path(args.changelog), changelog_dir))


if __name__ == "__main__":
    main()
