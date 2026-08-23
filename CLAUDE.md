# Context for Claude Code agents working on keyroost

## ⚠️ FIRST: sync with GitHub before doing any local work

Claude Code Web is making passes on this repo and **pushing commits to GitHub**,
so the GitHub remote is now the source of truth and the local checkout is
frequently behind. **Before starting any local work (and before committing),
check the remote and integrate it:**

```bash
git fetch origin
git log --oneline HEAD..origin/main   # what landed on the remote that we don't have
git status                            # branch + divergence
```

If `origin/main` (or the branch you're on) has moved ahead, **pull/rebase onto
it before writing code or committing** — do not build on a stale local tree, and
do not push a branch that diverged without reconciling first (we hit exactly
this and had to untangle a rejected push). When in doubt, stop and surface the
divergence to the user rather than committing on top of stale state.

## What this repository is

Independent, MIT/Apache-2.0 dual-licensed Rust toolchain for programming the
Token2 Molto2 / Molto2v2 programmable TOTP hardware token. Built from scratch
based on observation of the device protocol; not a fork of Token2's Python
tool. Workspace contains:

| Crate | Purpose | External deps |
|---|---|---|
| `keyroost-proto` | Pure-Rust protocol layer (SM4, SHA-1, APDU builders, MAC) | none |
| `keyroost-transport` | PC/SC reader discovery, Molto2 session, YubiKey CCID serial, OATH + OpenPGP applets | `pcsc`; `aes`/`des`/`cipher`/`getrandom`/`zeroize` (PIV mgmt-key auth); `hidapi` (non-Linux HID) |
| `keyroost-hid` | USB HID enumeration of FIDO devices via sysfs | `hidapi` (non-Linux only; Linux uses sysfs) |
| `keyroost-ctap` | FIDO2/CTAP-HID transport, CBOR, PIN protocols, credential mgmt, largeBlob | RustCrypto (`sha2`/`hmac`/`aes`/`cbc`/`p256`/`aes-gcm`), `rand_core`, `zeroize`, `miniz_oxide` (largeBlob DEFLATE); `hidapi` (non-Linux HID) |
| `keyroost-oath` | Pure-Rust Yubico/Trussed OATH (TOTP/HOTP) byte layer (APDU + TLV) | `zeroize` |
| `keyroost-openpgp` | Pure-Rust OpenPGP Card v3.4 byte layer (APDU + BER-TLV) | `zeroize` |
| `keyroost-piv` | Pure-Rust PIV (SP 800-73-4) byte layer; full management (status, GENERAL AUTHENTICATE, key-gen, cert import, PIN/PUK/mgmt-key, reset) + SPKI/PEM | `zeroize` |
| `keyroost-ias` | Pure-Rust IAS Classic/ECC (ISO 7816-4/-8) byte layer for cards like the Thales eToken 5300; built without a reference spec or hardware to trace against — see "Known soft spots" below | `zeroize`; `keyroost-piv` (its `x509`/`x509_parse`/`spki` DER modules only — never PIV protocol bytes) |
| `keyroost-token2otp` | Pure-Rust Token2 OTP-on-FIDO management byte layer (APDU + HID framing, ECDH+AES seed encryption) | RustCrypto (`sha2`/`aes`/`cbc`/`p256`), `rand_core`, `zeroize` |
| `keyroost-token2prog` | Pure-Rust Token2 2nd-gen single-profile programmable-token protocol (SM4 seed/MAC, config TLV); reuses `keyroost-proto` | `zeroize` |
| `keyroost-keyring` | Friendly-name registry (`keys.json`); serial matching, no hardware | `serde`, `serde_json` |
| `keyroost-resolve` | Shared key-identity resolution (USB + CCID serials, topology match) | in-tree only |
| `keyroost-rsakey` | Host-side RSA-2048 keygen + PKCS#1/PKCS#8 (PEM/DER) loading for OpenPGP import | `rsa`, `rand`, `zeroize` (scoped exception) |
| `keyroost-import` | otpauth:// + Aegis / 2FAS / otpauth-list parsers | `zeroize`; `serde`/`serde_json` (behind `bulk`); `scrypt`/`aes-gcm`/`base64` (behind `encrypted`, for Aegis vaults) |
| `keyroost-qr` | QR 2FA import from PNG/JPEG screenshots + Google Authenticator migration batches (always built; the GUI's separate `qr` feature gates *screen capture*, not this) | `rqrr`, `png`, `jpeg-decoder`, `zeroize` |
| `keyroost-screengrab` | Windows-only GDI screen capture for QR-from-screen; the sole `unsafe` FFI crate; inert on non-Windows | `windows-sys` (Windows only) |
| `keyroost-winwebauthn` | Windows-only non-admin FIDO2 helper: detect a FIDO key, open Windows' security-key settings, relaunch elevated; inert on non-Windows | `windows-sys` (Windows only) |
| `keyroostctl` | CLI binary | `clap` (+ `clap_complete`/`clap_mangen`), `serde`/`serde_json`, `zeroize` |
| `keyroost` | egui desktop GUI | `eframe`, `egui`, `serde`/`serde_json`, `zeroize`, `base64`, plus platform UI deps (`arboard`, `rfd`, `pollster`, `png`; Linux `ashpd`/`x11rb` behind the `qr` feature); `winresource` as a Windows-only **build**-dependency (embeds the icon + version info into `keyroost.exe`; never linked into any binary, never compiled off Windows) |

## Where to start reading

1. **`docs/PROTOCOL.md`** — wire format reference. APDU opcodes, the SM4-CBC
   MAC, the config TLV. Written about the device itself; doesn't reference any
   third-party implementation.
2. **`docs/BRINGUP.md`** — step-by-step plan for first-time hardware bring-up.
   This is the runbook the user wants to execute. Steps 1, 2 and 4 are
   read-only; step 3 writes a title to slot #99, step 5 writes a seed there,
   and step 6 bulk-imports into #95 onwards. Step 3 also offers a full-device
   wipe as the forgotten-key recovery path.
3. **`crates/keyroost-proto/src/`** — the protocol layer is the cleanest place
   to understand command construction. Start with `commands.rs`.

## The user's immediate goal

Program their Molto2 from a machine they control, with Claude Code running
locally so debug output and APDU hex traces can be diagnosed in-context. The
workflow during bring-up is:

1. User runs `keyroostctl --debug <subcommand>`.
2. If something looks wrong (status word other than `9000`, garbled response,
   wrong on-device behavior), agent diffs the captured hex against
   `docs/PROTOCOL.md` and edits the offset / framing in
   `crates/keyroost-proto/src/commands.rs` (response parsing and command
   construction both live there).
3. `cargo build --release` and retry. The binary is exposed on PATH via a
   symlink (`~/.local/bin/keyroostctl -> target/release/keyroostctl`), so a
   rebuild is live immediately — no copy step. (`~/bin` is intentionally not
   used; on systems where `~/.cargo/bin` and `~/.local/bin` are already on
   PATH, the symlink needs no further setup.)

## Known soft spots — most likely places for first-contact bugs

- **`get info` response layout** — parsed by `keyroost_proto::commands::parse_info`
  (`crates/keyroost-proto/src/commands.rs`), not in the transport;
  `Session::read_info` only transmits and delegates. The 3-byte preamble and
  2-byte separator are still uninterpreted, and `info[3]` is still *assumed* to
  be the serial-string length. Malformed input is safe — the parser is
  bounds-checked and fuzzed (`fuzz/fuzz_targets/molto_parse.rs`), with a
  `serial_len = 0xFF` regression test — so the live risk is a wrong *meaning*,
  not a crash. If a real device's serial reads garbled, that offset is the
  first suspect.
- **MAC framing (RESOLVED — do not re-litigate).** The MAC AAD header uses CLA
  `0x80` while the wire APDU uses `0x84`. This is confirmed device behaviour,
  not a guess: it is pinned by the known-answer suite
  (`crates/keyroost-proto/tests/known_answer_vs_python.rs`), independently
  reproduced with byte-exact expected APDUs in `keyroost-token2prog`, and
  Molto2 writes are hardware-verified. If a secure command is rejected with
  `SW 6A 80`, look at the payload, not at the class byte.
- **Lock / unlock APDUs** are still intentionally not implemented — no `0xD8`
  builder exists in `keyroost-proto`. The evidence needed is now reachable
  though: the hidden `keyroostctl molto probe --yes --include-destructive`
  will exercise `0xD8` (it is listed in `DESTRUCTIVE_INS` and skipped by
  default). Probe before writing a builder.

### IAS Classic/ECC — built without a reference spec, none of this is confirmed

`keyroost-ias` / `IasSession` / `keyroostctl ias` / the GUI's "IAS" tab were
built entirely from general ISO 7816-4/-8 knowledge — no ANSSI IAS-ECC
referential, no Thales/IDPrime command reference, and no eToken 5300 (or any
IAS card) to trace against. Every byte value below is a documented guess, not
a confirmed one; expect the first real bring-up to land on one or more of
these, fixed the same way the PIV soft spots above were: an isolated
point-edit, not a rewrite.

- **AID.** `keyroost_ias::CANDIDATE_AIDS` is a best-effort guess list — IAS
  Classic/ECC has no single spec-mandated AID the way PIV/OpenPGP do; each
  card issuer registers its own. `--aid <hex>` (CLI) / the GUI's "AID
  override" field (in the IAS tab's status card) exist so a real AID can
  be tried immediately, without a code change. Trace SELECT first, before
  anything else.
- **PIN/PUK/admin-key reference bytes** (`PIN_REF_USER`, `ADMIN_KEY_REF` in
  `crates/keyroost-ias/src/lib.rs`) are placeholders. `SW 6A88` (reference
  data not found) on VERIFY/CHANGE REFERENCE DATA is the first suspect.
- **GENERATE ASYMMETRIC KEY PAIR's INS byte and CRT tag layout.** `0x46`
  (ISO 7816-8's own table) vs `0x47` (what this workspace's own PIV/OpenPGP
  layers use for the identical concept) are both real conventions; `SW 6D00`
  means try the other INS before assuming the CRT shape (tag `0xB8` wrapping
  `0x80`/`0x84`) is wrong.
- **The admin-key crypto** (`admin_crypt` in
  `crates/keyroost-transport/src/ias.rs`) is the single highest-uncertainty
  piece of the whole feature: cipher (3DES/AES), mode, and whether a MAC is
  required are all unconfirmed guesses. Kept isolated in one function
  specifically so a full rewrite here doesn't ripple into the CLI/GUI.
- **The per-slot certificate FID table** (`Slot::default_cert_fid`,
  `FidTable`) is a 3-entry guess. `--fid <slot>=<hex>`-style overrides (via
  `FidTable`, threaded through `IasSession::open`) exist so correcting a
  real card's layout is a config change, not a rewrite.
- **`set_pin_retries` always returns `IasNotSupported`, on purpose.** No
  ISO 7816-4/-8 instruction covers it and no defensible placeholder byte
  sequence exists (unlike the other guesses above, which at least follow a
  reasoned convention) — see the doc comment on
  `IasSession::set_pin_retries`.
- **No applet reset exists in this feature at all**, not even as a guess —
  there's no basis to assume IAS-ECC profiles expose a full-applet factory
  reset the way PIV/OpenPGP do. This is a deliberate gap, not an oversight.

## Conventions

- **Don't push to remote without explicit user permission.** Local commits are
  fine; `git push` only when the user says so.
- **Vendor over depend.** SM4, SHA-1, base32, hex, CBOR, TLV, and otpauth
  parsing are all in-tree. External deps are limited to a small, deliberate set
  of scoped exceptions — the transport/UI boundary (`pcsc`, `clap`,
  `eframe`/`egui` + platform UI crates, `serde`), FFI-only crates
  (`hidapi` off-Linux, `windows-sys` on Windows), and vetted RustCrypto/`rsa`/
  `scrypt`/`aes-gcm`/`zeroize`/`getrandom` where hand-rolling the primitive
  would be irresponsible (see the per-crate deps in the table above). No new
  deps without a discussion first. One narrow in-tree exception:
  `keyroost-ias` takes a path dependency on `keyroost-piv` for its
  `x509`/`x509_parse`/`spki` DER modules only (CSR/self-signed-cert
  building, SPKI encode/decode) — that code is algorithm-shape-driven, not
  PIV-protocol-driven, and forking it a second time was the wrong call when
  the existing implementation is already tested. Never treat this as
  precedent for byte-layer crates depending on each other generally.
- **No documentation files unless explicitly asked.** `docs/` holds the protocol
  references, the bring-up runbook, the device-research record, and the
  published Learn site (`docs/*.html`, deployed by `pages.yml`); don't add more
  without asking.
- **Tests first when changing the protocol layer.** The known-answer suite in
  `crates/keyroost-proto/tests/known_answer_vs_python.rs` locks in byte-level
  agreement with an independent third-party SM4 implementation. Any change to
  command construction must keep those tests green or be paired with a written
  justification for the new expected bytes.
- **Linux build prerequisite:** `sudo apt install libpcsclite-dev pcscd` for the
  CLI; the GUI additionally needs `libxkbcommon-dev libwayland-dev libxcb1-dev
  libgl1-mesa-dev` (full per-distro list in the README's "Smart-card
  prerequisite" section). GUI crate MSRV is 1.92; the rest of the workspace 1.85.

## Running

```bash
# the whole workspace test suite
cargo test --workspace --offline

# CLI
cargo run -p keyroostctl -- --help
cargo run -p keyroostctl -- --debug molto info   # `info` lives under the `molto` group

# GUI
cargo run -p keyroost
```

## Release process

**`packaging/RELEASING.md` is the playbook — follow it top to bottom.** The one
rule to know here: before any version bump or tag, prove the packaging with the
mandatory build-only probe `gh workflow run linux-bundles.yml --ref <ref>` (no
tag input = build-only; an agent may approve that gate). Both the flatpak and
AppImage jobs must go green first. Packaging pulls from upstreams that drift
independently of our code (the v0.7.3 flatpak broke at release time because an
upstream source was pruned); such breaks must surface on a probe, not during the
release run.

## Commit style

The repo uses descriptive commits oriented around *why*, not *what*. See
`git log --oneline` for examples. Sign off via the standard footer the harness
appends (it carries the co-author and session lines); don't hand-write a model
identifier into the commit subject or body yourself.

## Privacy & secrets (enforced — see `.claude/`)

This is a security-key management tool. Treat PINs, credential listings, and
host secrets as untouchable. A PreToolUse hook (`.claude/hooks/guard.sh`)
enforces the rules below; **don't try to work around the guard** — if it
blocks something, that's intended.

- **Destructive FIDO ops** (`keyroostctl fido reset`, `fido creds-delete`) are
  irreversible. This checkout is used only with disposable **test keys**, so
  the guard no longer blocks them — still treat them with care and never point
  them at a security key in real use.
- **Never print or read secrets.** Don't `printenv`, don't `echo` a
  PIN/password/token variable, don't read `.env`, `*.pem`, SSH keys, or
  NetworkManager / `wpa_supplicant` WiFi configs. (Hook-blocked.)
- **PIN entry is the user's job.** PINs come from `--pin-env` / `--pin-stdin`
  the user sets in their own shell. Don't ask for the PIN, don't place it in
  argv, don't read it back.
- **Credential listings are private.** `fido creds-list` reveals which services
  the user has accounts with. Don't run it speculatively; if the user shares
  output, don't echo usernames / RP names beyond what the task needs.
- **Safe to run freely against any key:** `keyroostctl doctor`, `keyroostctl list`,
  `keyroostctl fido info`, `keyroostctl fido pin-retries` (read-only, no PIN, no
  counter change).
