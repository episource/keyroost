# Release-day playbook

The whole cut, in order, from a clean tree to every channel verified. Run it
top to bottom; nothing here is optional unless marked so. Written after
v0.7.5/v0.7.6 — the traps called out below all actually happened.

Conventions: the maintainer runs everything that signs or publishes; an agent
may prepare branches and approve **build-only probe** gates, never a
publishing gate. Version placeholder below: `vX.Y.Z`.

## 1. Pre-flight (no version bump yet)

- [ ] `git fetch origin` — main clean, no unlanded branches you meant to ship.
- [ ] CI green on main (includes the CHANGELOG/Cargo.toml drift guard and the
      pinned-inputs check).
- [ ] `cargo audit` green (the audit workflow runs on pushes; check the last
      run) and the deps-outdated report reviewed.
- [ ] **Publish-readiness check** (one command):
      `packaging/check-publish-readiness.sh v<prev>`
      Proves the crates.io fanout can actually run. Three failure modes, none
      of which any other gate catches and all of which surface only once the
      fanout is already half done:
      (a) a crate added since the last release — Trusted Publishing over OIDC
      cannot CREATE a crate name, so its first publish must be manual, with a
      crates.io Trusted Publishing entry added after;
      (b) a member missing from `publish.yml`'s list, which then silently
      never publishes;
      (c) a NEW inter-crate dependency edge that the publish order does not
      respect — cargo refuses to publish a crate whose path-dep sibling is not
      yet on crates.io at the pinned version, and the run dies with half the
      workspace released.
      (c) is the subtle one: every crate can already be published and the
      release still breaks, because what changed is the ORDER requirement, not
      the set. v0.7.7 added `keyroost-resolve -> keyroost-openpgp` and happened
      to be ordered correctly; nothing would have caught it if it had not been.
      The script cannot see Trusted Publishing config (no API exposes it) — for
      a newly-added crate, confirm that by hand in the crate's crates.io
      settings.
- [ ] **Packaging probe** (mandatory, one command):
      `gh workflow run linux-bundles.yml --ref main`
      No tag input = build-only; approve the gate (probe-safe). Both bundle
      jobs must go green, with "wrote N `<release>` entries" in their logs.
      Packaging pulls from upstreams that drift on their own schedule — the
      v0.7.3 flatpak broke at release time because an upstream source was
      pruned. Probes catch that; release runs must not.
- [ ] **Packaged-crate asset check** — every file a crate *references* must be
      a file it *ships*:
      `cargo package -p keyroost --no-verify --offline`
      `tar tzf target/package/keyroost-*.crate | grep -i '\.ico'`
      Confirm every path `build.rs` reads (and any `include_str!`/
      `include_bytes!` across the workspace) is inside the tarball. Cargo
      packages only files beneath the package root, so a path reaching outside
      it — `../../packaging/...` — silently vanishes from the published crate
      while still resolving fine in a git checkout. That is how the Windows
      icon broke `cargo install keyroost` before v0.7.7: nothing catches it,
      because `cargo publish` runs its verification build on Linux where
      `build.rs` is a `#[cfg(not(windows))]` no-op, and no workflow builds the
      packaged tarball at all. Hence `crates/keyroost/assets/keyroost.ico`.
      Note you cannot *build* the unpacked tarball at this stage: it resolves
      its sibling `keyroost-*` deps from crates.io at the new version, which is
      not published yet. Contents are the check here; the build is step 6.

## 2. Version bump + changelog (prep branch)

- [ ] Branch off main. Bump the workspace version: every
      `version = "<old>"` in the Cargo.tomls (the workspace field plus the
      inter-crate path-dep pins — `grep -rn 'version = "<old>"' --include=Cargo.toml .`).
- [ ] `cargo update --workspace` at the root AND in `fuzz/` (its own lock).
- [ ] CHANGELOG: add the `## [X.Y.Z] - date` section and the compare links.
      The top entry MUST match the new workspace version —
      `python3 packaging/flatpak/gen-metainfo-releases.py --check` proves it
      (CI enforces the same).
- [ ] **Breaking changes → `docs/migration.html`.** If this release renames a
      flag, moves a command, or changes a library signature, add its section
      (exact before → after) — the README points users there as the canonical
      record, and the Pages deploy rides on the `docs/**` change.
- [ ] **Full documentation audit — EVERYTHING, not a diff review.** Audit all
      of it against the code as it will ship: every `docs/*.html` Learn page,
      `README.md` top to bottom, and the meta-docs (`SECURITY.md`,
      `CONTRIBUTING.md`, `TODO.md`, `packaging/*.md`, `docs/*.md`,
      `CHANGELOG.md` link integrity). Reviewing only what changed since last
      time is exactly how the v0.7.8 audit's findings accumulated: pages
      claiming the inverse of shipped behavior (the Settings-tab gating),
      contributor credit trailing by five PRs, a binaries table missing the
      signed assets for three releases, and TODO items describing defects
      already fixed. Documentation drifts wherever code changed *around* it,
      so the untouched files are the ones that rot.
      The mechanical core: verify every CLI invocation in every page against
      the release binary's real `--help` tree (not the source); check
      contributor credit against `git log --format='%an' | sort -u` and the
      PRs since the last release; confirm every claim a page makes about GUI
      gating/behavior against the code; and walk every link FROM the app TO
      the site — the `learn_url(...)` callers in `crates/keyroost/src/ui/`
      are the inventory, and each slug must resolve against `docs/`. That
      direction is the one the audit never used to check, which is how the
      GUI shipped three releases linking a /devices page that did not exist
      (#99). Parallel audit agents (Learn pages /
      README / meta-docs) cover this in one pass; findings are fixed on the
      prep branch so the release ships accurate docs.
- [ ] Full gates: clippy `-D warnings`, fmt, workspace tests.
- [ ] Land on main via the signing flow (rebase over origin/main re-creates
      the commit signed; push `HEAD:main`).

## 3. Tag and watch the build

- [ ] **Pre-tag delta review.** Review the full release delta before
      tagging: `git log --oneline <previous-tag>..HEAD` to walk it, then
      `git diff <previous-tag>..HEAD` for anything unfamiliar. Commits on
      main are not individually signed; the tag signature is the only
      cryptographic statement covering the release, and SECURITY.md
      documents that it is made after this review. Each contribution was
      reviewed at merge (`packaging/REVIEWING.md`); this pass reviews the
      aggregate.

- [ ] `git tag -s vX.Y.Z -m "keyroost vX.Y.Z" && git push origin vX.Y.Z`
      (`v*` tags are admin-only by ruleset.)
- [ ] Two workflows start on the tag: `release.yml` (platform archives +
      GitHub Release) and `linux-bundles.yml` (AppImage + flatpak).
      **Approve both release-publish gates promptly and together** — the
      bundle attach steps wait for the Release that release.yml creates.
      The retry window is 10 minutes (v0.7.6 lost the old 2-minute window
      by 16 seconds); if it still expires, re-run the failed job once the
      Release exists — attach is idempotent (`--clobber`).
- [ ] When both finish, the Release must hold: 3 platform archives,
      `SHA256SUMS`, `keyroost-x86_64.AppImage` (+ `.sha256`, `.zsync`),
      `keyroost.flatpak` (+ `.sha256`). Check:
      `gh release view vX.Y.Z --json assets --jq '[.assets[].name]'`

## 4. Fanout (publish.yml)

- [ ] Approve the fanout's release-publish gate.
- [ ] **Verify each channel actually PUBLISHED — a green job can mask a
      no-op** (missing secrets skip-with-notice; caches lag):
  - crates.io: the two binaries publish last, so this one check covers the
    dependency chain —
    `curl -fsSL -H "User-Agent: keyroost-release" https://crates.io/api/v1/crates/keyroostctl/X.Y.Z`
  - Homebrew: `curl -fsSL https://raw.githubusercontent.com/framefilter/homebrew-keyroost/main/Formula/keyroost.rb | grep version`
  - AUR: check the **push line in the job log** first
    (`master -> master` to aur.archlinux.org); the RPC
    (`https://aur.archlinux.org/rpc/v5/info?arg[]=keyroost-bin`) lags a few
    minutes behind and reads stale right after the push.
    The job now **tolerates the upstream freeze specifically**: that one
    message logs a `::warning` and exits 0, so a frozen AUR no longer reds a
    release in which every other channel published. Any other clone failure
    is still fatal. A warning here means `keyroost-bin` was NOT updated —
    re-run the job once pushes reopen.
    **`The AUR is down due to maintenance. We will be back soon.` is not
    our bug and not worth retrying.** It comes from `aurweb/git/serve.py`
    *after* our deploy key authenticates, and has exactly one trigger: an
    operator set the maintenance flag and our source IP is not in the
    exception list. An IP ban would say something else ("The SSH interface
    is disabled for your IP address"), so this message never means we were
    blocked. The AUR froze *all* pushes on 2026-08-01 during a supply-chain
    malware incident and v0.7.7 shipped without it.
    Two traps: the freeze is announced **only on the aur-general mailing
    list** (not archlinux.org/news, no web banner), and the web UI, RPC and
    git-over-HTTPS reads all stay up throughout — so "the site works" tells
    you nothing about whether pushes do. Check
    <https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/>
    before assuming it is transient. AUR is independent of every other
    channel and can land late.
  - Flatpak remote (a machine with the remote configured):
    `flatpak update --appstream && flatpak remote-info keyroost io.github.framefilter.keyroost`
    must show the new version.
  - **winget: a skip with the "HOLDING for the Token2-signed build" notice
    is the DESIGNED outcome at this stage** — see step 5. A hard failure
    here means the `WINGET_TOKEN` PAT died (the job fails loudly on an
    expired token; renew the classic PAT, `public_repo` scope).

## 5. Signed Windows build (out-of-band, Token2)

- [ ] Ask Token2 to sign the **current** release's Windows build (never an
      older version — it would predate shipped fixes). They deliver into
      issue #77 as `signed_keyroost-vX.Y.Z-*.zip` attachments; macOS may
      arrive separately from Windows, so check for both.
- [ ] **The winget-pkgs fork sync now runs in CI** (`Sync the winget-pkgs
      fork`, non-fatal). wingetcreate submits its PR from that fork and
      cannot fast-forward it itself: `WINGET_TOKEN` is a classic PAT with
      `public_repo` scope, and pushing upstream commits that touch
      `.github/workflows/` needs the `workflow` scope. Left alone the fork
      drifts thousands of commits behind and the job dies at the very end
      with "The forked repository could not be synced with the upstream
      commits" — *after* Authenticode verification passed and the manifests
      were generated, so it reads as a signing problem and is not one
      (v0.7.7).
      If that sync step logs a warning, do it once by hand and re-run the
      job — the warning prints the command:
      `gh repo sync framefilter/winget-pkgs --source microsoft/winget-pkgs`
      Syncing is lossless while the fork is 0 ahead. **Granting `workflow`
      scope to `WINGET_TOKEN` retires the manual path for good** — the CI
      step then succeeds unattended.
- [ ] When it arrives: attach as **NEW** assets
      `keyroost-vX.Y.Z-windows-x86_64-signed.zip` + `.sha256` (and
      `keyroost-vX.Y.Z-macos-universal2-signed.pkg` + `.sha256`, unwrapped
      from its transport zip). Names are built from the tag by the job and
      matched literally — a near-miss reads as "not attached" and it holds
      again. **Never replace the CI-built assets** — that invalidates
      `SHA256SUMS`, provenance attestations, and any open winget PR's hash.
- [ ] Worth verifying the signed bytes are *our* build before attaching.
      Authenticode appends a certificate table, so stripping it (and zeroing
      the PE checksum + cert directory entry) must reproduce the CI binary
      byte-for-byte; at v0.7.7 it did. macOS cannot be checked this way —
      `codesign` rewrites the Mach-O in place — so there, confirm the Apple
      chain, the Developer ID signer, and universal2 slices instead.
      Note the `.pkg` is signed but **not notarization-stapled** (true since
      at least v0.7.6): Gatekeeper validates online, which fails offline.
- [ ] `gh workflow run publish.yml -f tag=vX.Y.Z` and approve the gate.
      Every channel no-ops (idempotent); the winget job Authenticode-verifies
      every PE in the signed zip (signer logged in the run) and submits the
      manifest. Confirm the winget-pkgs PR opened and (eventually) merged —
      Defender validation false positives on fresh binaries do happen; the
      documented remedies are a pipeline re-run (~18h cycles) or a WDSI
      false-positive report, not resigning.
      Judge this run by the **winget job's own conclusion**, not the run's
      overall status: any other channel that is failing for its own reasons
      (a frozen AUR, say) reds the whole run while winget is fine.
- [ ] Manual fallback from Linux if wingetcreate misbehaves:
      `komac update Framefilter.Keyroost --version X.Y.Z --urls <signed-asset-url> --submit`

## 6. Post-release

- [ ] Install-matrix spot check as machines allow: `cargo install keyroostctl`,
      flatpak update on a real install, AppImage launch, brew upgrade, winget
      after step 5.
- [ ] **`cargo install keyroost` on Windows** — the one configuration that
      actually compiles `build.rs` and embeds the icon from the published
      tarball, and the only place a missing packaged asset shows up. Only
      possible here, once the sibling crates are live (see the pre-flight
      asset check for why it cannot run earlier). If this ever fails, the fix
      belongs under the crate root, not in a wider `include`: cargo cannot
      package paths above the package directory.
- [ ] `keyroostctl --version` / GUI About shows X.Y.Z.
- [ ] Close/comment the issues the release fixes (drafts usually prepared
      during the work); announcement if any.
- [ ] Out-of-band corrections later (metadata fixes, asset re-attach): use the
      dispatch republish — `packaging/LINUX-BUNDLES.md` "Out-of-band runs".
      A republish builds from the dispatched ref into the tag's release and
      is version-guarded against tree/tag mismatch.
