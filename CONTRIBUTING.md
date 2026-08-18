# Contributing

Contributions are warmly welcome — code, docs, hardware test reports, and
issue reports alike. This file collects the practical details in one place.

## How a PR lands

PRs are reviewed against `packaging/REVIEWING.md`, then squash-merged. The
squash commit carries your authorship. CI for outside contributors runs
after maintainer approval of the workflow run, so there can be a delay
between opening a PR and checks starting. Contributions are credited in the
changelog and, for a first contribution, in the README's Contributors
section.

## Before you open a PR

Run the same gates CI does:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

MSRV is Rust 1.85 for the workspace (1.92 for the `keyroost` GUI crate).

Two project rules worth knowing up front:

- **Vendor over depend.** Most primitives are implemented in-tree on purpose;
  new external dependencies need a discussion first (open an issue).
- **Reference issues as `re #N`**, not `fixes #N` — the maintainer closes
  issues after verification, and auto-close keywords bypass that.

A hardware-verified fix is worth calling out in the PR description: this
project manages security keys, and "reproduced and verified on my device"
carries real weight (see [#96](https://github.com/framefilter/keyroost/pull/96)
for a model example).

## Where to find work

`TODO.md` is the live task list. Items under "Ready to pick up" are
self-contained; items under "Blocked" say what they're waiting on.

## Licensing

keyroost is dual-licensed MIT OR Apache-2.0. By submitting a contribution you
agree it is licensed the same way, per Apache-2.0 §5 — there is no CLA.

## Security issues

Please don't open a public issue for a vulnerability — see
[SECURITY.md](SECURITY.md) for the private reporting path.
