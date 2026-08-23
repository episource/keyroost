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

### IAS Classic/ECC — built without a reference spec for the eToken 5300 itself

`keyroost-ias` / `IasSession` / `keyroostctl ias` / the GUI's "IAS" tab were
built from general ISO 7816-4/-8 knowledge with no eToken 5300 (or any IAS
card) to trace against. **The user's real eToken 5300 rejected every
CANDIDATE_AIDS guess with `SW 6A82`** (PIV's standard AID failed the same
way, confirming this device genuinely has no PIV applet — it's IAS-only).
Reading the ATR the user captured
(`3b ff 96 00 00 81 31 fe 43 80 31 80 65 b0 84 56 51 10 12 01 78 82 90 00 6a`)
against OpenSC's own ATR table identified the real chip family precisely:
this is a **Gemalto/Thales IDPrime** card (`SC_CARD_TYPE_IDPRIME_930_PLUS`/
`_940`, ATR-table label "eToken 5110+ FIPS") — a specific, better-documented
sibling of the generic "IAS Classic/ECC" applet family this feature was
originally named after, with its own dedicated OpenSC driver
(`card-idprime.c`/`pkcs15-idprime.c`). Three sources have now
corrected/confirmed parts of the byte layer — none is authoritative *for the
eToken 5300 specifically* (no wire-level manual for that exact product is
public), but all are real:

- **OpenSC's `card-cedulauy.c`** — a real, deployed open-source driver for
  Uruguay's national eID, a related-but-distinct IAS-Classic-family card
  (Gemalto RID, different PIX/issuer). Confirmed the signing sequence and
  MSE:SET framing below.
- **OpenSC's `card-idprime.c`**, plus GitHub issue #3488 and its fix PR
  #3493 (a real bring-up report *for this exact chip family*, SafeNet
  eToken 5100/5110 SC) — the strongest evidence source so far, since it's
  an actual APDU trace against IDPrime silicon, not just driver source.
  Confirmed the AID, PIN field shape, MSE algorithm-reference byte, and GET
  CHALLENGE `P2` below.
- **Thales's public Common Criteria Security Target** for "IAS Classic v5.2
  with MOC Server v3.1 on MultiApp V5.0" (D1506187_LITE rev 1.5) — a CC
  assurance document, not a command reference, so it gives no
  AID/INS/P1/P2/tag detail, but it does describe the admin-key crypto's
  real *shape*. The actual byte-level manual for that card family is
  Thales's restricted "IAS Classic v5.2, Reference Manual, D1542053B" — not
  publicly available.

Confirmed (adopted, no longer `[GUESS]`):
- **SELECT's P2 is `0x00`** ("return FCI"), not PIV/Yubico's `0x0C`.
- **`CANDIDATE_AIDS`' first entry is the real IDPrime applet AID**
  (`A0 00 00 00 18 80 00 00 00 06 62`, from `card-idprime.c`'s
  `idprime_path`), ahead of Uruguay's cedulauy AID — **now confirmed
  working against two real devices**: the user's SafeNet eToken 5300 and a
  second card, a genuine IDPrime 930. `keyroostctl ias status` succeeds
  end-to-end on both (`AID: a000000018800000000662` in the printed status),
  and both expose the *same* three cert-file IDs this crate already
  guessed (`Slot::default_cert_fid`) — `SELECT FILE` by FID `0001`/`0002`
  succeeds on both, `0003` correctly comes back `6A82` (empty key-management
  slot) on both. One caveat: `open_ias`'s `set_debug` is applied *after*
  `IasSession::open()` returns (a pre-existing pattern shared with every
  other applet session in this CLI, not IAS-specific), so the SELECT
  exchange itself never appears in a `--debug` trace — we know it succeeded
  only because `open_ias` didn't return `NoIasApplet`, not from which exact
  candidate (full AID vs. its truncated-prefix fallback) actually matched.
- **A one-byte-truncated prefix of that AID** (`A0 00 00 00 18 80 00 00 00
  06`) is the second `CANDIDATE_AIDS` entry, relying on ISO 7816-4's
  partial-DF-name SELECT matching — the exact mechanism `keyroost-piv`
  already uses for PIV's own AID (`keyroost_piv::AID` is PIV's 11-byte AID
  truncated to its 5-byte RID/PIX prefix, hardware-verified earlier in this
  project). This hedges against the real card's AID differing from
  `card-idprime.c`'s only in a trailing version/variant byte. Deliberately
  *not* truncated all the way to the bare 5-byte Gemalto RID
  (`A0 00 00 00 18`) as a default try — that RID is shared across many
  unrelated Gemalto/Thales applets (MD, PIV-compatible, OpenPGP-like), so
  an automatic RID-only match risks ambiguity or the wrong applet on a
  multi-applet card; `--aid a000000018` is there if a trace ever calls for
  going that short deliberately.
- **`PIN_REF_USER` is `0x11`**, not `0x01` — confirmed by issue #3488's real
  APDU trace (`00 20 00 11 06 31 32 33 34 35 36`).
- **PIN/PUK fields are 16 bytes, `0x00`-padded**, not PIV's 8-byte
  `0xFF`-padded field — confirmed by issue #3488 / PR #3493's exact APDU.
  `pad_pin()` now accepts 4–16 byte secrets (was 4–8).
- **MSE:SET DST's algorithm-reference byte is `0x42` (RSA) / `0x44` (EC)**
  — confirmed by `card-idprime.c`, and deliberately kept on a separate
  method (`KeyAlg::mse_sign_algo_id`) from the still-unconfirmed
  `KeyAlg::id()` used only by GENERATE, so this evidence can't silently
  leak onto a command it doesn't cover.
- **GET CHALLENGE's `P2` selects the challenge length** (`0x01` for 8
  bytes, `0x00` for 16) rather than being a fixed `0x00` — confirmed by
  `card-idprime.c`.
- **Signing is a three-step sequence**, not the single-step PSO:CDS this
  crate originally shipped: MSE:SET DST (`00 22 41 B6`, CRT tag `0xB6`
  wrapping key-ref `0x84` then algorithm-ref `0x80`, in that order) → PSO:LOAD
  HASH (`00 2A 90 A0`, tag `0x90` wrapping the same DigestInfo/hash this crate
  already computed for the old single-step form) → **empty-body**
  PSO:COMPUTE DIGITAL SIGNATURE. `IasSession::sign` now takes `slot` and
  drives all three; MSE's status word is intentionally not checked (a card
  that doesn't need it shouldn't abort signing — a card that does need it
  fails at the PSO steps instead, with a traceable status word).
- **PIN padding is card-type-*conditional*, not a single global rule — the
  earlier "PIN/PUK fields are 16 bytes, `0x00`-padded" entry above was
  itself wrong, caught by real hardware.** The 16-byte-padded encoding is
  real, but OpenSC's `pkcs15-idprime.c` only applies it for
  `SC_CARD_TYPE_IDPRIME_840`/`_940`/`_GENERIC`; every other IDPrime type —
  `_830`, `_3810`, `_930`, `_930_PLUS` — is left at `stored_length = 0`,
  i.e. **unpadded**, sent at its own exact length (still `[HIGH]`: this is
  quoted directly from that driver's source, not inferred). Proven live:
  the user VERIFYing their IDPrime 930's genuine factory PIN (`"0000"`) got
  a false wrong-PIN rejection (`63 Cx`, with the retry counter for real
  decrementing) under the old always-padded encoding — the padding itself
  was the bug, not the PIN value. `needs_padded_pin()` now ports OpenSC's
  own ATR+mask table (`IDPRIME_ATR_TABLE`) so `IasSession::open` decides
  per-session from the card's real ATR, defaulting to unpadded for any ATR
  that matches nothing (both OpenSC's own fallback and every real device
  traced in this project so far). `pad_pin()`/`verify_pin()`/
  `change_reference_data()`/`reset_retry_counter()` all take this as an
  explicit `padded: bool` rather than assuming one encoding. Confirmed by
  unit test against both real devices' exact ATRs (the user's eToken 5300 →
  `930_PLUS` → unpadded; their separate IDPrime 930 → `930` → unpadded) —
  matching `needs_padded_pin`'s output to what the table itself says both
  should be, not yet to a live VERIFY succeeding (the user hasn't reverified
  `"0000"` against the corrected encoding at time of writing).

Still open (unconfirmed, isolated so a fix is a point-edit):
- **Whether the corrected PIN encoding actually fixes the eToken 5300's
  `SW_SECURITY_NOT_SATISFIED` (`6982`) on VERIFY is untested.** The old,
  wrongly-always-padded encoding fully explains the IDPrime 930's `63 Cx`
  (wrong-PIN-shaped) rejection, but the eToken 5300 gave a *different*
  status word — `6982`, not `63 Cx` — for the same wrong bytes, which reads
  as a security-precondition failure rather than "PIN didn't match", so the
  encoding fix might not be sufficient there on its own. **The user's own
  leading hypothesis, not yet tested**: this specific eToken has a physical
  touch sensor gating private-key/PIN operations (a real feature on several
  SafeNet/Thales combo security keys), and VERIFY needs a touch either
  immediately before or during the command — which this crate's transport
  makes no attempt to prompt for or wait on (`transmit_full` is one
  synchronous `card.transmit()`; if the reader/card don't transparently
  stretch that call via T=1 WTX while waiting for a touch, a same-command
  touch requirement would need this crate to detect "waiting" and retry,
  which it doesn't do today). Not yet acted on in code — deliberately,
  since building retry/wait logic around a guessed touch protocol without a
  trace showing what the "waiting" state actually looks like on the wire (a
  `61xx`? a longer-than-usual `transmit()`? nothing distinguishable at all?)
  would be exactly the kind of unconfirmed guess this file exists to flag.
  `--pin-env`/`--pin-stdin` on `keyroostctl ias status`/`export-cert`
  (`IasSession::status_with_pin`, `IasSlotStatus::pin_required`) are what
  surfaced this finding and remain the right tool for the next experiment,
  now against the corrected encoding; `ias status`'s new `PIN encoding:`
  line reports which one a session picked without needing `--debug`.
- **`ADMIN_KEY_REF`** is still a placeholder. `SW 6A88` (reference data not
  found) on EXTERNAL AUTHENTICATE/CHANGE REFERENCE DATA is the first
  suspect.
- **GENERATE ASYMMETRIC KEY PAIR's own INS byte and CRT layout** — `0x46`
  vs `0x47`, and CRT tag `0xB8` (algo-then-keyref) — are still guesses.
  Neither the cedulauy nor the IDPrime evidence above covers on-card key
  generation; `SW 6D00` means try the other INS.
- **The admin-key crypto** (`admin_crypt` in
  `crates/keyroost-transport/src/ias.rs`) is still the single
  highest-uncertainty piece of the whole feature, and is known to likely be
  the wrong *shape*, not just the wrong bytes: the Security Target above
  confirms TDES/AES as the ciphers (matching `IasAdminAlg`) but shows the
  real scheme is Diffie-Hellman/ECDH ephemeral session-key establishment
  feeding actual secure messaging (separate encrypt + MAC per command), not
  a static-key GET CHALLENGE/EXTERNAL AUTHENTICATE challenge-response.
  Kept isolated in one function specifically so replacing it with the real
  key-exchange + secure-messaging scheme doesn't ripple into the CLI/GUI.
- **The per-slot certificate FID table** (`Slot::default_cert_fid`,
  `FidTable`) is a 3-entry guess. `--fid <slot>=<hex>`-style overrides exist
  so correcting a real card's layout is a config change, not a rewrite.
- **`set_pin_retries` always returns `IasNotSupported`, on purpose.** No
  ISO 7816-4/-8 instruction covers it and no defensible placeholder byte
  sequence exists — see the doc comment on `IasSession::set_pin_retries`.
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
