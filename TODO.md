# keyroost TODO

**This is the single live task list.** History lives in git — completed work is
recorded in `CHANGELOG.md` and the commit log, not here. When something lands,
delete the item rather than ticking it; when something is decided, move the
decision to "Standing decisions" at the bottom so it is not re-litigated.

Deliberately unversioned: the previous `TODO-v0.7.5.md` / `TODO-hardening.md`
pair rotted because version-named files accumulate layers nobody rereads.

Current work: **v0.7.8** — a patch release backing out the v0.7.7 OTP
capability regression (see #95).

---

## In flight

Being worked on right now — check with whoever holds it before starting.

(Nothing at the moment.)

---

## Ready to pick up

- **Capabilities need a third state: unknown.** `Caps` is a bitset, so a
  capability is either present or absent and there is nowhere to record "we
  could not check". On a USB-HID-only enumeration nothing has been sent to the
  device, so with no way to say *unknown*, absence of evidence gets written down
  as absence of the feature — and something has to invent that answer.
  That is the whole of the v0.7.7 OTP argument. It did not cause a user-facing
  regression (capabilities are insert-only, so a real probe always wins), but it
  is why a guess was needed at all. Where a capability does go missing it bites
  hard: no GUI tab, and `--key <name>` cannot find the device.
  What exists to build on: `keyroost-transport` (`src/lib.rs`, the `answers(...)`
  block) `SELECT`s each applet AID over a reader — ground truth. The CLI already
  models the third state elsewhere: `otp_feature_supported` returns
  `Option<bool>` with `None` meaning "can't tell, so go ahead". The device list
  never got the same treatment.
  Shape to aim for: present / absent / unverified per capability, surfaces
  driven off it, and the difference rendered — "OTP — not verified, no reader
  available" rather than no tab at all. Unverified always behaves as "offer it";
  the attempt then produces a real answer, which is now a decent message rather
  than a raw protocol error.
  Note a HID probe is not the fix on its own: it costs an open plus up to a 3 s
  wait per key on a listing meant to be instant, it can collide with another
  process holding the hidraw node, and it only answers whether the applet is
  reachable *over HID* — Token2's Bio3 carries OTP over CCID with HID disabled,
  so a HID probe returns the same wrong answer more slowly. Unverified is the
  honest result there, not a second guess.
  Not blocked on anyone. A data-model change across resolve, the CLI and the
  GUI.

- **Run the mandatory packaging probe before any version bump.**
  `gh workflow run linux-bundles.yml --ref <ref>` with no tag input = build-only;
  both the flatpak and AppImage jobs must go green *before* any version bump or
  tag. Packaging pulls from upstreams that drift independently (the v0.7.3
  flatpak broke at release time because a source was pruned). Full sequence:
  `packaging/RELEASING.md`, which is the playbook for the whole release.

- **PC/SC: `dlopen` libpcsclite at runtime instead of hard-linking it** — the
  real fix for [#47](https://github.com/framefilter/keyroost/issues/47).
  Two payoffs: the *host's* libpcsclite is always used (the only client
  guaranteed to match the host's `pcscd`, for every distribution channel, not
  just the AppImage), and when it is absent keyroost still launches with
  FIDO/USB-HID working and the PC/SC panes showing "PC/SC unavailable".
  Removes the known limitation documented in
  `packaging/appimage/build-appimage.sh`. The `pcsc` crate links at build time —
  check whether it exposes a dynamic-load path or whether we wrap libpcsclite in
  a thin FFI loader ourselves. Design first; verify on a host with and without
  the library.

- **CTAP-over-NFC chaining: second GET RESPONSE sends a fixed `Le = 00`.**
  `crates/keyroost-ctap/src/ctap_pcsc.rs:193` ignores the `61xx` length hint —
  the same shape as the transport bug fixed in the v0.7.7 security round, left
  out of scope there because it is pre-existing.

- **README + Learn site: point the Windows download at the signed asset.**
  Signed zips now exist (Token2 signs out-of-band on a hardware token), but
  `README.md`'s Windows direct-download section still names only the CI zip.
  Add the pointer plus a short note that the signed build may trail the release
  by a few days. winget availability is unaffected — it holds for the signed zip
  by policy.

- **Responsive layout at high zoom / narrow window.** At ~200% zoom in a
  partial-screen window, horizontal rows overflow and overlap (top-bar Reset vs
  the brand; section-header right-actions over the left text). Fullscreen is
  fine. Fix: elide the left text in those header rows (`Label::truncate`) so the
  right action always has room, and tidy/wrap the top-bar cluster. Cheap partial
  fix: raise the minimum window width. Low-priority polish. (S–M)

- **UI liveness — make "busy" visibly different from "frozen".** Card I/O stalls
  the visible UI for seconds (touch-required sign/decrypt/authenticate, on-card
  RSA keygen, the ~30s reset re-insert window, PC/SC enumeration) and a static
  frame reads as a hang. There is a worker thread and a spinner on imports, but
  it is inconsistent. Needs a coherent activity language: a global working
  indicator while the device worker is busy, per-action busy/disabled button
  states, a cue on long ops. Keep it tasteful — over-animation reads as cheap.
  Research what feels alive vs. annoying before building.

- **Drop the broken-pipe workaround when stable Rust lands the SIGPIPE fix.**
  `install_broken_pipe_guard()` in `crates/keyroostctl/src/main.rs` plus its
  `tests/broken_pipe.rs` guard exist only because the clean fix — libstd
  resetting `SIGPIPE` to `SIG_DFL` — is nightly-only today
  (`-Zon-broken-pipe=kill`; tracking issue rust-lang/rust#97889). Check
  periodically; when it reaches stable, delete both and adopt the built-in.
  (Same applies to the `keyroost` GUI binary if it ever grows piped stdout.)

---

## Blocked / needs someone else

- **[#37] OnlyKey support — blocked on hardware** (units ordered). Teach
  `keyroost-resolve` to recognize `1d50:60fc` / product `ONLYKEY`, label it
  "OnlyKey", and treat serial `1000000000` as a non-unique placeholder (fall
  back to the hidraw path). Today OnlyKey appears only in the GUI AAGUID table.
  **Must be done as part of this work, not after:** the post-replug reinsert
  matcher identifies a key by serial, and every OnlyKey ships the *same* serial,
  so it would currently accept a different OnlyKey as "the same key".

- **Lift the "experimental" label on the Token2 PIN+ standards applets ([#23])
  — needs PIN+ hardware.** Verify OATH / OpenPGP / PIV over CCID on a real PIN+
  key. Token2 may be able to help, given the collaboration.

---

## Hardware verification

Not yet run. Everything here is behaviour that automated tests cannot reach;
items marked *(no hardware)* need a device the maintainer does not have.

**Device binding and targeting** (deferred from the v0.7.5 security work — the
plan's two-key manual steps were never executed):

- **Wrong-device bindings, GUI:** with two keys plugged in, switch the selection
  mid-operation and confirm the stale completion is discarded for Molto2 session
  open/write, the FIDO advanced dialog (a typed PIN must die with the dialog),
  OATH delete confirmation, OpenPGP reset modal, fingerprint enroll, and
  large-blob ops.
- **Armed FIDO reset:** arm for key A, replug key A → fires; arm for key A,
  insert a same-model key B during the window → must NOT fire; a serial-less key
  must refuse to arm. *Partly exercised already* — the wrong-key refusal path
  was hit on hardware and fixed in `55adf2f`; the arm-and-fire and
  refuse-to-arm paths remain.
- **CLI targeting:** with two OTP-capable keys, `keyroostctl --device <name> otp
  list` / `molto info` must hit the named key only; ambiguous or duplicate-serial
  setups must fail closed with the ambiguity error.
- **GUI OTP pane binding:** two OTP-capable keys — list/add/delete operate on the
  selected key only, and the fail-closed error appears when the transport pick
  cannot be satisfied.
- **Duplicate-serial advisory:** with two same-serial keys connected, the sidebar
  advisory appears and both keys stay separately selectable.
- **Linux hidraw bounded reads:** unplug a key mid-`fido info` — the command must
  error within the read budget, not hang.

**Feature verification:**

- **OATH applet reset:** on a password-PROTECTED test key, reset from the GUI
  locked view and via `keyroostctl oath reset --yes`; confirm credentials are
  wiped, the password is cleared, and the pane re-lists empty and unlocked.
- **OATH password carry:** on a password-protected key, unlock + list, then
  "Read code" on an HOTP credential — must succeed without retyping; switch
  devices and confirm the retained password is dropped.
- **SSH-cert extract, interop proof:** on a YubiKey 5.7, store a cert with
  `fido2-token -S -b -n ssh:… cert.pub`, extract it with `keyroostctl fido
  ssh-cert extract` (and via the GUI), and confirm the output `-cert.pub` is
  byte-identical to the original — the cross-implementation check a round-trip
  KAT cannot provide. Also try a cert written by an OLDER libfido2 (pre-~2021),
  which wrote ZLIB-wrapped (RFC 1950) largeBlob data rather than raw DEFLATE:
  keyroost's `inflate_raw` accepts raw only, so an old-format blob will not
  extract. Decide whether to also accept zlib, as libfido2's reader does.
- **Card-content identity ([#83])** *(no hardware)*: with a Token2 PIN+
  smartcard in a GENERIC reader (Alcor / SCM / Realtek), confirm keyroost shows
  vendor "Token2" and the FULL serial (not the 8-digit one); that it still does
  in the Token2 dual reader; that a non-Token2 OpenPGP card (e.g. Nitrokey)
  shows its correct registry vendor; and that a model rejecting GET_INFO over
  contact falls back to the 8-digit serial with no error.
- **v0.7.6 field fixes** *(no hardware)*: the Settings tab + Reset on a CTAP
  2.0-only key ([#81] — the reporter's device class), and the standalone Reset
  card on a key with a blocked or absent PIN. (#82's HID→CCID fallback only
  engages on the quirky firmware; reporter confirmation stands in.)
- **Windows GUI icon** *(no hardware — needs a Windows machine)*: confirm the
  embedded icon shows in Explorer and the taskbar, and that Linux/macOS builds
  are unaffected (the `winresource` build-dep is host-gated). Future signed GUI
  binaries should then be byte-identical to CI plus a signature, with nothing
  injected.

---

## Deferred to a later release

- **musl static Linux build** — under consideration, notes-only, not wired into
  any workflow. The draft design and runbook are in `packaging/musl/README.md`;
  the recommendation there is CLI-only (`keyroostctl`), never a musl static GUI.
  Fixes the glibc-version portability caveat; the wrinkle is `libpcsclite`
  linking for the PC/SC path (and the dlopen item above changes that calculus).
  Think it through before committing.

- **Full branch protection** (require PR + green CI on `main`) — deliberately
  deferred: it ends the direct-push workflow. Adopt when release cadence slows
  and the product is feature-complete. The light protections are already in
  place: `v*` tag create/update/delete is admin-only, and `main` rejects
  force-push and deletion.

---

## Standing decisions

Not tasks. Kept so they are not re-litigated or re-researched.

- **No HID workarounds for Token2 R3.2+/R3.3+ keys — the channel is off by
  design.** The "no-status-word HID dialect" that #82 and #95 were both filed
  about (the `80 bf 00 01 05` / "status word 0x0105" response) is not a dialect
  to support: Token2 confirmed on #95 that HID-HOTP is absent on these models
  and the HID channel ships disabled on purpose (an active HID channel makes
  the OS treat the key as a keyboard, and on Windows it needs admin rights).
  CCID is the intended path, auto-transport prefers it, and the error for a
  declined HID probe now points at the CCID fix. Do not resurrect "teach the
  HID path to speak this format" — there is nothing to speak to, and what the
  dead channel echoes when poked is not worth settling.

- **No device→capability matrix. Ever.** keyroost does not decide what a device
  can do by looking its USB product id up in a table. Capabilities come from
  asking the device — `SELECT` the applet and see what answers — or they are
  *unknown*, and unknown means offer the surface and let the attempt report the
  truth.
  A matrix cannot be maintained: it drifts every time a vendor ships a new
  configuration, we have no way to test entries against hardware we do not own,
  and keeping it current would mean asking the vendor to confirm rows forever.
  v0.7.7 proved the failure mode in a single day — an entry was wrong, the wrong
  entry silently removed a feature, and the only way to find out was a user
  reporting it.
  This settles the v0.7.7 `Caps::OTP` question: the product-id gate is **not**
  coming back, not narrowed, not with a corrected table. Nothing here is blocked
  on a vendor answer.
  What a product id is still good for: **labelling** ("Bio3 Dual (FIDO + PGP)")
  and colouring an error message. Never for granting or withholding a surface.
  `TOKEN2_PRODUCTS` says as much in its own docs — "nothing here may be treated
  as proof that an applet is present" — and the inverse is no safer.

- **Windows signing: keep signing with Token2; winget always waits for the
  signed zip.** No own signing identity for now — Azure Artifact Signing /
  Certum would put the maintainer's legal name in the cert CN, and SignPath's
  OSS programme rejected the project as too new (re-apply 6–12 months from
  2026-07). Signed bytes carry SmartScreen reputation across releases and move
  the submission off the release-day critical path. Submitting unsigned-first-
  then-refreshing was rejected: two PRs per release doubles validation exposure.
- **Signed assets are attached, never substituted.** Token2's signed build ships
  as a NEW asset (`keyroost-vX.Y.Z-windows-x86_64-signed.zip` + `.sha256`).
  Replacing a CI-built asset would invalidate `SHA256SUMS`, the provenance
  attestations, and any open winget PR's hash. The two variants have
  complementary trust chains (CI provenance vs Authenticode) — label which is
  which in the release notes. The mechanics (including the `komac` manual
  fallback from Linux) live in `packaging/RELEASING.md` step 5.
- **Defender/SmartScreen false positives are about prevalence, not signing.**
  Researched 2026-07-17: no "unsigned variant of normally-signed software"
  heuristic exists — reputation keys on signing-cert identity and per-file hash
  only. The v0.7.5 `Validation-Defender-Error` was the documented
  low-prevalence false positive that hits brand-new binaries, signed ones
  included; it cleared on a moderator re-run. Don't re-derive this.
- **Do NOT host Token2's signed v0.7.4** — it predates the v0.7.5 security
  fixes. Always ask them to sign whatever is current.
- **Flathub is intentionally skipped** (its stance against AI-authored code);
  distribution is the self-hosted signed OSTree remote plus the offline
  `.flatpak` bundle.
- **crates.io first publishes are manual and ordered.** The OIDC job cannot
  create a brand-new crate, so any crate added since the last release needs a
  one-time `cargo publish` plus a Trusted Publishing entry first. Order (wait
  ~a minute between tiers for index propagation): (1) `keyroost-proto`,
  `keyroost-hid`, `keyroost-keyring`, `keyroost-rsakey`; (2) `keyroost-ctap`,
  `keyroost-oath`, `keyroost-openpgp`, `keyroost-piv`, `keyroost-token2otp`,
  `keyroost-import`; (3) `keyroost-transport`, then `keyroost-resolve` and
  `keyroost-qr`; (4) `keyroostctl`, `keyroost`.
- **Release verification is per-channel, not per-job.** The crates.io / Homebrew
  / winget / AUR jobs skip-with-a-notice and still exit `success` when their
  secret is absent, so a green check can mask a no-op. Confirm the version
  actually appeared in each catalog. (winget's `WINGET_TOKEN` now fails loudly
  on expiry rather than skipping silently.)
