//! PIV (NIST SP 800-73-4) over PC/SC.
//!
//! Drives the PIV smartcard application using the pure-byte builders/parsers in
//! [`keyroost_piv`]. Like the OATH and OpenPGP sessions, this adds the card
//! transmit, the `61xx` / GET RESPONSE reassembly loop, reader discovery, the
//! status view (version/serial/PIN-retries/per-slot certs), and the full
//! management surface: management-key mutual authentication (the AES/3DES
//! witness/challenge round — the only place this crate does block-cipher math),
//! PIN/PUK change and unblock, set-pin-retries, set-management-key, key
//! generation, certificate import/export, and applet reset.

use crate::gzip::gunzip_capped;
use crate::{trace, TransportError};
use keyroost_piv as piv;
use keyroost_piv::{KeyAlg, Metadata, MgmtAlg, PinPolicy, PublicKey, Slot, TouchPolicy};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::collections::{BTreeSet, HashMap};
use zeroize::Zeroizing;

/// How many wrong-credential attempts to make when intentionally blocking a
/// PIN or PUK during a factory reset: always more than the card's reported
/// retry count so a block is guaranteed, but hard-capped so a card that
/// misreports (or never decrements) cannot loop forever.
fn block_attempts_cap(reported: Option<u8>) -> u32 {
    reported.map(u32::from).unwrap_or(10).min(20) + 2
}

/// A throwaway 8-ASCII-digit credential for the loops that deliberately block a
/// PIN/PUK during a factory reset, drawn fresh from the host RNG and never equal
/// to `previous`.
///
/// Eight digits is a legal PIV **and** OpenPGP credential (both store 6–8
/// bytes), so the card evaluates the attempt and decrements its counter instead
/// of rejecting it on length. Drawing it fresh matters: any constant compiled in
/// here is also a value a card may legitimately hold, and this source is
/// published — a "wrong" guess that turns out to be right consumes no try at
/// all, and on the PUK path it rewrites the PIN. `previous` is excluded because
/// some applets refuse an unchanged credential without counting the attempt.
/// Shared with the OpenPGP applet's factory reset.
pub(crate) fn random_credential_guess(
    previous: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let mut raw = Zeroizing::new([0u8; GUESS_LEN]);
    // No fallback to a constant: a factory reset that can't draw fresh entropy
    // has to stop, not go back to guessing something predictable.
    getrandom::getrandom(&mut raw[..]).map_err(|_| TransportError::HostRngFailed)?;
    Ok(credential_guess_from(&raw, previous))
}

/// Length of a blocking-loop guess, in ASCII digits.
const GUESS_LEN: usize = 8;

/// The deterministic half of [`random_credential_guess`]: fold raw entropy into
/// ASCII digits, then step off `previous` if the draw happened to collide with
/// it. (Split out so the collision path is testable without stubbing the RNG.)
fn credential_guess_from(raw: &[u8; GUESS_LEN], previous: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let mut guess = Zeroizing::new(Vec::with_capacity(GUESS_LEN));
    for byte in raw.iter() {
        guess.push(b'0' + byte % 10);
    }
    // A repeat is astronomically unlikely but would waste an attempt on an
    // applet that ignores an unchanged credential; bump the last digit rather
    // than re-rolling so this can never spin.
    if previous == Some(guess.as_slice()) {
        let last = GUESS_LEN - 1;
        guess[last] = b'0' + (guess[last] - b'0' + 1) % 10;
    }
    guess
}

/// Re-map an error raised by the final RESET step of [`PivSession::factory_reset`]
/// onto what the card is actually left holding.
///
/// By that point the PIN and the PUK are deliberately blocked, so a card that
/// *permanently* refuses RESET is a card keyroost can no longer finish: the
/// single-applet `piv reset` sends the identical instruction and gets the
/// identical refusal. Only the permanent refusals are rewritten — a transport
/// fault (card pulled, reader gone) and an unspecific or transient status word
/// are not the card saying "this instruction does not exist", and re-running
/// the factory reset against a quiescent applet is still right there. The
/// callers append that re-run hint to everything left falling through.
fn map_reset_stage_error(e: TransportError) -> TransportError {
    match e {
        // Two refusals, and only two, are the card's final word.
        //
        // 6983 or 6985 (both mapped to PivResetNotAllowed): the card checked
        // the one precondition RESET has and says it is unmet — with the PIN
        // and PUK already blocked, a second run reaches the same check and
        // gets the same answer, so there is nothing left to retry.
        //
        // 6D00 (INS not supported) / 6A81 (function not supported): the
        // vendor-extension RESET instruction is not implemented at all. No
        // amount of retrying conjures it.
        //
        // Everything else the card can answer under this label — 6F00 (no
        // precise diagnosis), 6881, a 6A82 from an applet that momentarily
        // lost its selection after the blocking loops — says nothing about
        // RESET being unavailable, so it must NOT be rewritten into a verdict
        // of "permanently unusable". 6982 is deliberately absent for the same
        // reason: RESET is not gated behind a security state, so a card
        // answering "security status not satisfied" is in an unexpected
        // transient state rather than declaring RESET impossible.
        TransportError::PivResetNotAllowed
        | TransportError::Apdu {
            label: "piv reset",
            sw1: 0x6D,
            sw2: 0x00,
        }
        | TransportError::Apdu {
            label: "piv reset",
            sw1: 0x6A,
            sw2: 0x81,
        } => TransportError::PivResetIncomplete(
            "the PIN and the PUK are now both blocked, but the card refused the \
             RESET instruction, so the PIV applet was NOT wiped. Its keys and \
             certificates are still on the card and there is no keyroost command \
             that can finish this — `keyroostctl piv reset` sends the very \
             instruction the card just refused. The PIV part of the card is \
             unusable until whoever issued or made it resets it with their own \
             tooling. Any non-PIV applets on the same key (FIDO, OATH, OpenPGP) \
             are unaffected.",
        ),
        other => other,
    }
}

/// A read-only snapshot of a PIV application's state.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct PivStatus {
    /// The PIV applet's own version. Ordinarily the reply to Yubico's
    /// proprietary `GET VERSION` extension (`INS FD`), raw bytes, any
    /// non-empty length — real Yubico firmware answers with exactly 3
    /// (`major.minor.patch`), but this extension is implemented by many
    /// devices beyond genuine YubiKeys (observed: a Swissbit iShield Key 2
    /// Pro, an OpenFIPS201 build, answering `9000` with 4 bytes that don't
    /// trace back to anything in OpenFIPS201's own source), so a reply here
    /// means "answers this Yubico extension," not "is a YubiKey." When a
    /// specific fingerprint's own probe supplies an applet version instead
    /// (currently: HID Crescendo, via its GET PIV PROPERTIES response's own
    /// "Applet Version Block" — that fingerprint never answers the Yubico
    /// extension at all), that one is used instead. `None` when neither
    /// source answers. [`Self::feature_gate`] (via [`keyroost_piv::compat`])
    /// compares this directly as a byte slice rather than requiring an exact
    /// 3-byte shape. See [`keyroost_piv::format_version_bytes`] for display
    /// formatting.
    pub version: Option<Vec<u8>>,
    /// The applet's own firmware version, when a specific fingerprint's probe
    /// discovered one — currently a Nitrokey (`Trussed(NitroKey)`, via
    /// Trussed's admin application) only. Not necessarily equal to
    /// [`Self::version`]: that field is the *PIV applet's* own version
    /// (Yubico's `GET VERSION` extension, when the card answers it at all), a
    /// different number on cards where this one is populated. `None` when no
    /// such probe applies to this fingerprint, or the probe ran and found
    /// nothing parseable — same best-effort degradation as [`Self::applet_name`].
    pub version_firmware: Option<Vec<u8>>,
    /// Device serial number. Ordinarily the Yubico GET SERIAL extension
    /// (widened to `u128` — see [`keyroost_piv::parse_serial`]); when a
    /// specific fingerprint's own probe supplies a serial instead (currently:
    /// a Nitrokey's admin application), that one is used and GET SERIAL is
    /// skipped entirely — a Nitrokey answers that Yubico extension too, but
    /// with a number that isn't its real serial. `None` when neither source
    /// answers.
    pub serial: Option<u128>,
    /// Remaining PIN tries from a no-op VERIFY (`63 Cx`); `Some(0)` when blocked,
    /// `None` when the card didn't report a count.
    pub pin_retries: Option<u8>,
    /// Per-slot certificate presence, in canonical slot order.
    pub slots: Vec<PivSlotStatus>,
    /// The card's CHUID (FASC-N, GUID, expiration), when it has one. A
    /// read-only, best-effort read: a transport failure degrades to `None`
    /// rather than failing the whole status snapshot (see [`PivSession::status`]).
    pub chuid: Option<keyroost_piv::Chuid>,
    /// Best-effort fingerprint of the PIV applet implementation — from ATR
    /// and SELECT-response text, but also from whether a specific applet can
    /// be selected by AID at all (e.g. Feitian's registered RID) and, in
    /// general, from whether the card supports a particular instruction; see
    /// [`keyroost_piv::fingerprint`] for the full scheme. `Generic` when
    /// nothing more specific matched, not when fingerprinting itself failed.
    pub applet_fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    /// The token's own name, when a specific one was actually discovered:
    /// currently a Nitrokey's admin application (for
    /// [`AppletFingerprint::Trussed`](keyroost_piv::fingerprint::AppletFingerprint::Trussed)`(`[`NitroKey`](keyroost_piv::fingerprint::TrussedVariant::NitroKey)`)`),
    /// a YubiKey's own major version (for
    /// [`AppletFingerprint::YubiKey`](keyroost_piv::fingerprint::AppletFingerprint::YubiKey)),
    /// or HID Crescendo's SELECT response Application Label (for
    /// [`AppletFingerprint::HidCrescendo`](keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo)`(`[`C2300`](keyroost_piv::fingerprint::HidCrescendoVariant::C2300)`)`/[`C4000`](keyroost_piv::fingerprint::HidCrescendoVariant::C4000)`)`).
    /// Empty otherwise — deliberately not backfilled with the generic
    /// [`keyroost_piv::fingerprint::AppletFingerprint::applet_name`] for
    /// `applet_fingerprint`, so a caller can tell "this card told us its own
    /// name" apart from "we only classified the applet family". A caller
    /// wanting something to show either way falls back to `applet_fingerprint`
    /// itself (its `Display` impl, or `applet_fingerprint.applet_name()`).
    pub applet_name: String,
}

/// Whether a given PIV key slot holds a certificate (and its size).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PivSlotStatus {
    pub slot: piv::Slot,
    /// True when GET DATA returned a certificate object for the slot —
    /// including one that cannot be read (see [`Self::cert_unreadable`]).
    pub cert_present: bool,
    /// Length in bytes of the certificate's DER encoding, as read from the
    /// card, when present. This is the DER itself — the card's own `0x53`
    /// object framing (the `70`/`71`/`FE` TLVs wrapping it) is not counted.
    /// `0` when the certificate is unreadable.
    pub cert_len: usize,
    /// `Some` when the slot holds a certificate that cannot be read, and why.
    /// The slot is not empty: writing a new certificate replaces it.
    pub cert_unreadable: Option<CertUnreadable>,
}

/// Why a slot's certificate object holds a certificate that cannot be read.
/// Both cases are a certificate flagged gzip-compressed (CertInfo `71 01 01`,
/// as the tool that wrote the object may choose) whose compressed data won't
/// inflate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUnreadable {
    /// Not a gzip stream, or its compressed data is corrupt or cut off.
    Damaged,
    /// It inflates past the 64 KiB host ceiling on a certificate's size.
    TooLarge,
}

impl CertUnreadable {
    /// A stable machine-readable token (`damaged` / `too_large`).
    pub fn code(self) -> &'static str {
        match self {
            CertUnreadable::Damaged => "damaged",
            CertUnreadable::TooLarge => "too_large",
        }
    }
}

impl std::fmt::Display for CertUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CertUnreadable::Damaged => "its compressed data is damaged",
            CertUnreadable::TooLarge => "it decompresses to more than 64 KiB",
        })
    }
}

/// [`PivStatus`] plus the per-slot key/certificate detail a status pane
/// shows, gathered in the single pass [`PivSession::status_detailed`] makes.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PivStatusDetailed {
    /// The plain status snapshot — version, serial, PIN retries, CHUID, and
    /// per-slot certificate occupancy.
    pub status: PivStatus,
    /// Per-slot detail, in the same canonical slot order as `status.slots`.
    pub slots: Vec<PivSlotDetail>,
}

/// One slot's key algorithm, certificate Subject DN, and PIN/touch policy —
/// what [`PivSession::slot_key_algorithm`] and [`PivSession::slot_policy`]
/// each return, but read together so the slot's one GET METADATA and one
/// certificate GET DATA are shared rather than repeated.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PivSlotDetail {
    pub slot: piv::Slot,
    /// Key algorithm, or `None` when this card names no key for the slot (GET
    /// METADATA silent, nothing generated in this session, no certificate to
    /// parse). Same three-step fallback as [`PivSession::slot_key_algorithm`].
    pub algorithm: Option<KeyAlg>,
    /// The slot certificate's Subject DN, formatted; `None` when the slot has
    /// no certificate or its DN did not parse (degraded silently, as in the
    /// pane this feeds).
    pub subject: Option<String>,
    /// PIN and touch policy, or `None` when unavailable — not necessarily an
    /// empty slot; see [`PivSession::slot_policy`].
    pub policy: Option<(PinPolicy, TouchPolicy)>,
}

/// [`PivSession::identity`]'s resolved shape: this applet's
/// [`keyroost_piv::fingerprint::AppletFingerprint`] plus its reported
/// applet-version and firmware-version byte strings (either or both `None`
/// when the card never reported one) — everything
/// [`keyroost_piv::compat::resolve`]/[`keyroost_piv::compat::resolve_quirks`]
/// need to gate a [`keyroost_piv::compat::PivExtension`] or resolve a
/// [`keyroost_piv::compat::PivQuirk`]. Named fields rather than a tuple on
/// purpose: `version` vs. `version_firmware` is exactly the distinction that
/// went wrong when HID Crescendo's applet version was first wired up
/// (landed in the wrong axis, caught only in review) — a positional
/// `.0`/`.1`/`.2` (or a same-shaped tuple destructured in the wrong order)
/// can't fail that same way, since the compiler checks the field name at
/// every use.
#[derive(Clone)]
struct SessionIdentity {
    fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    version: Option<Vec<u8>>,
    version_firmware: Option<Vec<u8>>,
}

/// [`PivSession::applet_fingerprint`]'s resolved shape — see that method's
/// doc for what each field means. Named fields for the same reason as
/// [`SessionIdentity`]'s.
struct AppletFingerprintResult {
    fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    name: String,
    version: Option<Vec<u8>>,
    version_firmware: Option<Vec<u8>>,
    serial: Option<u128>,
}

/// How a caller is currently authorized to change the card-management key,
/// passed to [`PivSession::set_management_key`]/
/// [`PivSession::delete_management_key_hid_crescendo`]. Every fingerprint but
/// one ignores this — the standard SET MANAGEMENT KEY round relies on the
/// ordinary 9B security status a prior [`PivSession::authenticate_management`]/
/// [`PivSession::authenticate_management_via_pin`] call already established,
/// same as every other admin write in this module. The one exception is a
/// HID Crescendo unit whose "management key" isn't a real PIV object at all
/// (see [`PivSession::hid_crescendo_reports_management_key`]): there,
/// installing or deleting a key happens on a *different* applet instance
/// (the ACA), which needs its own unlock run fresh rather than assumed to
/// still be in force — see
/// [`PivSession::hid_crescendo_aca_put_xauth_key_op`].
#[derive(Debug, Clone, Copy)]
pub enum CurrentMgmtAuth<'a> {
    /// The current management key, for the standard round or ACA XAUTH's
    /// GET CHALLENGE / EXTERNAL AUTHENTICATE round.
    Key(&'a [u8]),
    /// A PIN, for a device with
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`].
    Pin(&'a [u8]),
}

/// What [`PivSession::factory_reset`] does for the PIV-only path, resolved
/// purely from this applet's [`keyroost_piv::compat::PivExtension::Reset`]
/// gate and [`keyroost_piv::compat::PivQuirk`]s — see
/// [`PivSession::plan_factory_reset`], which resolves this, and
/// [`PivResetPreview`], which wraps it alongside the device-wide
/// [`keyroost_piv::compat::PivExtension::ResetGlobal`] alternative
/// [`PivSession::factory_reset`] prefers when it's available (this type says
/// nothing about that axis on its own — see [`PivResetPreview::Global`]).
/// Exposed as its own public type — not just an internal branch inside
/// [`PivSession::factory_reset`] — so a whole-device factory reset can preview
/// the PIV-only shape up front and decide how to report the step (e.g.
/// "skipped: not supported" vs. a real failure) without duplicating the
/// decision or having to parse it back out of a [`TransportError`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryResetPlan {
    /// [`keyroost_piv::compat::FeatureGate::Unsupported`]: this fingerprint
    /// is known not to implement RESET at all. Deliberately blocking the
    /// PIN and PUK would have no way back, so [`PivSession::factory_reset`]
    /// refuses before touching either counter — unless
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`] offers something
    /// instead, in which case [`PivResetPreview::Global`] wins before this
    /// variant is even reached.
    Unsupported,
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`]: RESET
    /// needs an authenticated management-key session on this fingerprint,
    /// not the PIN/PUK-blocked precondition [`PivSession::factory_reset`]
    /// otherwise automates. It authenticates with the
    /// `current` credential its caller supplied, then sends RESET —
    /// refusing instead, with [`TransportError::PivResetNeedsManagementAuth`],
    /// only when no credential was supplied at all.
    NeedsManagementAuth,
    /// [`keyroost_piv::compat::FeatureGate::Unverified`]: support can't be
    /// confirmed, so [`PivSession::factory_reset`] skips its usual PIN/PUK
    /// pre-blocking (blocking both blindly on a device that might not
    /// implement RESET risks a permanent lock) and sends a bare
    /// [`PivSession::reset`] instead, succeeding or failing on the card's
    /// own terms.
    Unverified,
    /// [`keyroost_piv::compat::FeatureGate::Supported`] with no
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`] — the
    /// YubiKey convention, and the most-automated mechanism
    /// [`PivSession::factory_reset`] runs: burn the PIN, then the PUK, then
    /// RESET.
    BurnPinPukThenReset,
}

/// What [`PivSession::factory_reset`] will attempt for this applet's current
/// fingerprint, resolved read-only by [`PivSession::preview_factory_reset`] —
/// [`keyroost_piv::compat::PivExtension::ResetGlobal`] checked first (a
/// device-wide mechanism wins over a PIV-only one whenever it's available),
/// [`FactoryResetPlan`] (`PivExtension::Reset`'s own shape) as the fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivResetPreview {
    /// Neither `PivExtension::ResetGlobal` nor `PivExtension::Reset` is
    /// anything but a confirmed dead end: [`PivSession::factory_reset`] would
    /// refuse outright with [`TransportError::PivResetUnsupported`]. A
    /// whole-device factory reset should not even plan a PIV step for this
    /// device (`keyroost_resolve::exclude_unresettable_piv`).
    Unsupported,
    /// `PivExtension::ResetGlobal` resolves
    /// [`keyroost_piv::compat::FeatureGate::Supported`] or
    /// [`keyroost_piv::compat::FeatureGate::Unverified`]:
    /// [`PivSession::factory_reset`] will attempt
    /// the device-wide mechanism (HID Crescendo's ACA RESET CARD today),
    /// which takes PIV down with it alongside at least one other applet.
    /// Wins over [`Self::Piv`] even when `PivExtension::Reset` also offers
    /// something — a device-wide mechanism, once available, is the more
    /// complete reset.
    Global,
    /// `PivExtension::ResetGlobal` is a confirmed dead end but
    /// `PivExtension::Reset` isn't: [`PivSession::factory_reset`] will attempt
    /// a PIV-only reset, per this nested [`FactoryResetPlan`].
    Piv(FactoryResetPlan),
}

/// Outcome of a successful [`PivSession::factory_reset`]. Both variants mean
/// the applet (and, on the device-wide path, whatever else that mechanism
/// covers) was actually wiped — [`Self::WipedKeyRestoreFailed`] only
/// distinguishes a courtesy follow-up step that failed afterward, never
/// reachable unless the wipe itself already succeeded. Named for the outcome
/// generally, not just the device-wide path: every other path `factory_reset`
/// can take (the PIN/PUK burn dance, a bare unverified RESET, an
/// authenticated management-key RESET) only ever produces [`Self::Wiped`] on
/// success, since none of them has an equivalent courtesy follow-up step to
/// fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryResetOutcome {
    /// The PIV applet was wiped by one of the mechanisms confined to PIV
    /// itself ([`FactoryResetPlan`]'s shapes) — nothing outside PIV was
    /// touched. See [`Self::WipedGlobal`] for the device-wide counterpart.
    Wiped,
    /// [`PivSession::hid_crescendo_aca_reset_card`]-specific: the device-wide
    /// `PivExtension::ResetGlobal` mechanism ran cleanly — RESET CARD
    /// succeeded and XAUTH key 1 was restored to HID's documented
    /// factory-delivery value. This took at least one other applet down with
    /// PIV, so a caller building a report line should name the whole device,
    /// not just PIV (`keyroost_resolve`'s `PIV_GLOBAL_RESET_LABEL`) — unlike
    /// [`Self::Wiped`], which is confined to PIV alone.
    WipedGlobal,
    /// [`PivSession::hid_crescendo_aca_reset_card`]-specific: RESET CARD
    /// succeeded — the device IS wiped — but restoring XAUTH key 1 to HID's
    /// documented factory-delivery value afterward failed. XAUTH key 1 is
    /// left cleared (RESET CARD's own effect) rather than at the factory
    /// default; a caller should tell the user this distinctly from a hard
    /// failure, since the reset itself worked. Same device-wide scope as
    /// [`Self::WipedGlobal`] — only the courtesy restore is what's soft here.
    WipedKeyRestoreFailed,
}

/// What [`PivSession::hid_crescendo_aca_put_xauth_key_op`] should do to XAUTH
/// key 1 once unlocked — install a new key ([`Self::Set`], from
/// [`PivSession::set_management_key`]) or delete it outright ([`Self::Delete`],
/// from [`PivSession::delete_management_key_hid_crescendo`]). Private: an
/// implementation detail of how those two public methods share one
/// select/unlock/reselect sequence, not something a caller constructs
/// directly.
enum HidCrescendoXauthKeyOp<'a> {
    Set(MgmtAlg, &'a [u8]),
    Delete,
}

/// An open PIV applet session on one PC/SC reader.
pub struct PivSession {
    card: Card,
    debug: bool,
    /// True when the reader negotiated T=0 with the card. T=0 cannot carry
    /// extended-length APDUs at all (ISO 7816-3 — the protocol has no way to
    /// frame them), so every large-payload command must be chained from the
    /// start on such links. Learned from the connection, never from the
    /// card's make: a T=0 contact card that receives an extended-length APDU
    /// may simply go silent (issue #103 — the reader reported "transaction
    /// failed" and the #101 status-word fallback never got a status word to
    /// act on), so waiting for a refusal is not a strategy there.
    t0: bool,
    /// Algorithm + public key of any slot this session itself generated a key
    /// in, keyed by key reference. This is a fallback source only, for cards
    /// that don't answer GET METADATA (pre-5.3 firmware, or non-Yubico PIV):
    /// `slot_key` (the shared source for CSR/self-sign) falls back to this
    /// when metadata comes back empty. It's populated by `generate_key`, or
    /// explicitly by a caller via [`Self::remember_pubkey`] — never by reading a
    /// card back, so it's exactly as trustworthy as whoever put it there. It
    /// lives only as long as this session (a fresh `open()` on reconnect
    /// starts empty, and there is deliberately no on-disk or cross-process
    /// persistence — see [`Self::remember_pubkey`] for how a caller bridges
    /// that) and any operation that changes what's in a slot (`delete_key`,
    /// `move_key`, `reset`) invalidates the corresponding entries — see
    /// [`PivSession::slot_key`].
    pubkey_cache: PubkeyCache,
    /// Raw response body of the most recent SELECT (full or short AID) —
    /// the FCI a spec-compliant card returns since both builders request it
    /// via a case-4 `Le`. Feeds [`keyroost_piv::fingerprint::select_identity`].
    /// Empty when SELECT never returned a body (a card that answers `9000`
    /// with nothing), never `None`: fingerprint resolution treats empty and
    /// absent the same way.
    select_response: Vec<u8>,
    /// [`Self::identity`]'s cache: `None` until first resolved, then this
    /// applet's [`keyroost_piv::fingerprint::AppletFingerprint`] plus its
    /// reported applet/firmware version bytes, for the rest of the session.
    /// Safe to cache — unlike the read-through data this session
    /// deliberately doesn't cache (certs, PIN retries, slot occupancy; see
    /// [`Self::status_detailed`]'s doc) — because the applet's identity and
    /// reported versions cannot change while the card stays connected, but
    /// resolving them can cost a handful of extra APDUs (some fingerprints
    /// need a live SELECT probe), so it's worth not repeating per slot.
    /// [`Self::fingerprint`], [`Self::quirks`], and [`Self::extension_gate`]
    /// are thin accessors over this; [`keyroost_piv::compat::resolve_quirks`]
    /// and [`keyroost_piv::compat::resolve`] are themselves cheap pure table
    /// lookups, so there's no need to additionally cache their outputs.
    identity: Option<SessionIdentity>,
    /// [`Self::hid_crescendo_properties_raw`]'s cache: `None` until first
    /// resolved, then the raw response body of a HID Crescendo GET PIV
    /// PROPERTIES read (C2300 or C4000 — both families expose this, over
    /// differently-framed requests but with a compatible response
    /// structure), for the rest of the session — one read serves both the
    /// per-slot algorithm list ([`Self::hid_crescendo_slot_key_algorithms`]) and this
    /// applet's own version ([`Self::hid_crescendo_version`],
    /// [`Self::applet_fingerprint`]'s HID Crescendo branch), so this exists
    /// purely to avoid re-issuing that same read for each of those —
    /// including once per slot [`Self::status_detailed`] asks about. A read
    /// that fails caches as an empty `Vec`, same "resolved, with or without
    /// data" convention as [`Self::identity`].
    hid_crescendo_properties_raw: Option<Vec<u8>>,
}

/// The in-session public-key cache behind `PivSession`, keyed by PIV key
/// reference. Exactly five transitions exist, each mirroring the card
/// operation that makes it true; the session methods are one-line callers so
/// the unit tests below can pin the semantics without a live card:
///
/// * a fresh session starts empty (`new` — deliberately no persistence),
/// * `generate_key` / `remember_pubkey` make the slot's entry exactly the new
///   key (`remember`),
/// * `delete_key` leaves nothing to fall back to (`evict`),
/// * `move_key` relocates the key material, so its entry follows (`migrate`),
/// * `reset` wipes every slot (`clear`).
struct PubkeyCache(HashMap<u8, (KeyAlg, PublicKey)>);

impl PubkeyCache {
    fn new() -> Self {
        Self(HashMap::new())
    }

    /// The slot now holds exactly this key — `generate_key` minted it there,
    /// or the caller vouched for it via `remember_pubkey`. Replaces any
    /// previous entry: after a regenerate, the old pubkey must not survive to
    /// describe the new private key.
    fn remember(&mut self, key_ref: u8, alg: KeyAlg, key: PublicKey) {
        self.0.insert(key_ref, (alg, key));
    }

    /// The slot's key material is gone (`delete_key` succeeded): a stale
    /// entry here would produce a CSR/self-signed cert for a key that no
    /// longer exists. Evicting an uncached slot is a no-op.
    fn evict(&mut self, key_ref: u8) {
        self.0.remove(&key_ref);
    }

    /// The key itself relocated (`move_key` succeeded), not just its
    /// reference — carry a cached entry along with it rather than dropping
    /// it, so a subsequent CSR/self-sign at `dest` still works on
    /// metadata-less firmware, and leave nothing behind at `src`. An uncached
    /// `src` carries nothing and, crucially, invents nothing at `dest`.
    fn migrate(&mut self, src: u8, dest: u8) {
        if let Some(cached) = self.0.remove(&src) {
            self.0.insert(dest, cached);
        }
    }

    /// The applet was factory-reset (`reset`, which `factory_reset` also
    /// funnels into): every slot is empty, nothing cached survives.
    fn clear(&mut self) {
        self.0.clear();
    }

    fn get(&self, key_ref: u8) -> Option<&(KeyAlg, PublicKey)> {
        self.0.get(&key_ref)
    }
}

/// The management-key algorithms whose key is exactly `key_len` bytes, 3DES
/// first. Empty when no algorithm uses that length.
///
/// [`PivSession::resolve_management_key_algorithm`] uses this as its fallback
/// when GET METADATA is absent *and* the card accepts no GENERAL AUTHENTICATE
/// probe — i.e. when only the key length is left to go on. Only 24 bytes is
/// ambiguous (3DES and AES-192 share it); 3DES leads because it was the sole
/// pre-metadata option. 16 → AES-128 and 32 → AES-256 are unique; 8
/// (single-DES) and everything else map to nothing.
fn mgmt_algs_for_key_len(key_len: usize) -> &'static [MgmtAlg] {
    match key_len {
        16 => &[MgmtAlg::Aes128],
        24 => &[MgmtAlg::TripleDes, MgmtAlg::Aes192],
        32 => &[MgmtAlg::Aes256],
        _ => &[],
    }
}

/// Pick the management-key algorithm to authenticate with from the set the
/// card accepted a GENERAL AUTHENTICATE witness request for (`accepted`), given
/// the length of the key in hand. `None` when nothing fits `key_len`.
///
/// * `accepted` empty → the probe told us nothing; fall back to the
///   length-only table ([`mgmt_algs_for_key_len`]).
/// * otherwise keep only accepted algorithms whose key is `key_len` bytes.
/// * if that still leaves more than one — which can only be 3DES + AES-192,
///   the sole length collision (both 24 bytes) — prefer 3DES, the historical
///   pre-GET-METADATA default.
fn pick_mgmt_alg(accepted: &[MgmtAlg], key_len: usize) -> Option<MgmtAlg> {
    let by_len: Vec<MgmtAlg> = if accepted.is_empty() {
        mgmt_algs_for_key_len(key_len).to_vec()
    } else {
        accepted
            .iter()
            .copied()
            .filter(|a| a.key_len() == key_len)
            .collect()
    };
    if by_len.contains(&MgmtAlg::TripleDes) {
        return Some(MgmtAlg::TripleDes);
    }
    by_len.first().copied()
}

/// A fresh, random 16-byte CHUID GUID — host-side only, no card I/O. For
/// pre-filling (and, via a "refresh" action, regenerating) a "New CHUID"
/// GUID input before [`PivSession::new_chuid`] writes whatever the user
/// settled on — their own manual value included — to the card.
pub fn random_chuid_guid() -> Result<[u8; 16], TransportError> {
    let mut guid = [0u8; 16];
    getrandom::getrandom(&mut guid).map_err(|_| TransportError::HostRngFailed)?;
    Ok(guid)
}

/// Run [`crate::decode_bcd_serial`] over `serial`, but only when
/// [`keyroost_piv::compat::resolve_quirks`] finds
/// [`keyroost_piv::compat::PivQuirk::InsF8SerialIsBcd`] active for
/// `fingerprint` at `applet_version`/`firmware_version` — Token2 is the only
/// device seeded with that quirk so far; others may be discovered and added
/// to `keyroost_piv::compat`'s quirk tables later. Every other vendor's
/// serial is a plain integer already, and BCD-decoding one would corrupt it.
/// Shared by [`PivSession::status`] and [`PivSession::status_detailed`].
fn decode_serial_if_bcd(
    fingerprint: keyroost_piv::fingerprint::AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
    serial: Option<u128>,
) -> Option<u128> {
    let reports_bcd_serial =
        keyroost_piv::compat::resolve_quirks(fingerprint, applet_version, firmware_version)
            .contains(&keyroost_piv::compat::PivQuirk::InsF8SerialIsBcd);
    if reports_bcd_serial {
        serial.map(crate::decode_bcd_serial)
    } else {
        serial
    }
}

/// Strip `md`'s algorithm identifier (tag `0x01`) and public key (tag `0x04`)
/// when `quirks` contains
/// [`keyroost_piv::compat::PivQuirk::InsF7MetadataAlgorithmInvalid`] — on an
/// applet with that quirk, GET METADATA's algorithm byte has been observed
/// stuck and never reflecting the slot's actual key state, and the public key
/// goes with it: a raw key blob is meaningless without a trustworthy
/// algorithm to interpret it against (RSA vs. EC changes how those bytes are
/// structured, e.g. in [`metadata_key_material`]). Every other field
/// (`policy`, `origin`, `is_default`, `retries`) is untouched — the quirk is
/// specific to tags `0x01`/`0x04`. [`PivSession::metadata`] is the sole
/// caller; split out as a pure function, same seam style as
/// [`decode_serial_if_bcd`], so the stripping rule is unit-testable without a
/// card.
fn clear_metadata_if_quirky(
    quirks: &BTreeSet<keyroost_piv::compat::PivQuirk>,
    mut md: Metadata,
) -> Metadata {
    if quirks.contains(&keyroost_piv::compat::PivQuirk::InsF7MetadataAlgorithmInvalid) {
        md.algorithm = None;
        md.public_key = None;
    }
    md
}

impl PivSession {
    /// Connect to `reader_name` and SELECT the PIV application. Returns
    /// [`TransportError::NoPivApplet`] when the card has no PIV applet.
    /// Equivalent to [`Self::open_with_debug`]`(reader_name, false)` — see
    /// that constructor's doc for why a caller that wants `--debug`-style
    /// tracing of *this very SELECT* has to ask for it here, up front,
    /// rather than via [`Self::set_debug`] afterward.
    pub fn open(reader_name: &str) -> Result<Self, TransportError> {
        Self::open_with_debug(reader_name, false)
    }

    /// [`Self::open`], but with per-APDU stderr tracing already enabled for
    /// the initial SELECT this constructor itself issues. `open` followed by
    /// [`Self::set_debug`] — the only other way to turn tracing on — is
    /// always one APDU too late for that: the SELECT has already happened by
    /// the time `set_debug` runs, so it silently never appears in a
    /// `--debug` trace. Front ends that know their debug flag before opening
    /// (which is all of them — it comes from a CLI flag or a GUI setting,
    /// not from anything the card says) should call this instead of the
    /// open-then-set_debug pattern.
    pub fn open_with_debug(reader_name: &str, debug: bool) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let card = ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        let t0 = negotiated_t0(&card);
        let mut session = Self {
            card,
            debug,
            t0,
            pubkey_cache: PubkeyCache::new(),
            select_response: Vec::new(),
            identity: None,
            hid_crescendo_properties_raw: None,
        };
        session.select()?;
        Ok(session)
    }

    /// Enable per-APDU stderr tracing. Only affects APDUs sent *after* this
    /// call — [`Self::open_with_debug`] is the way to also trace the initial
    /// SELECT [`Self::open`]/this constructor issues before returning.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Names of connected readers whose PIV applet answers `SELECT` with `9000`.
    pub fn list_piv_readers() -> Result<Vec<String>, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let mut buf = [0u8; 4096];
        let names: Vec<std::ffi::CString> = ctx
            .list_readers(&mut buf)
            .map_err(TransportError::PcscUnavailable)?
            .map(|r| r.to_owned())
            .collect();
        let mut out = Vec::new();
        for name in names {
            if let Ok(card) = ctx.connect(name.as_c_str(), ShareMode::Shared, Protocols::ANY) {
                let t0 = negotiated_t0(&card);
                let mut session = PivSession {
                    card,
                    debug: false,
                    t0,
                    pubkey_cache: PubkeyCache::new(),
                    select_response: Vec::new(),
                    identity: None,
                    hid_crescendo_properties_raw: None,
                };
                if session.select().is_ok() {
                    out.push(name.to_string_lossy().into_owned());
                }
                // Release without resetting (pcsc's `Drop` hard-codes
                // ResetCard) — probing must not disturb cards other sessions
                // hold open.
                let _ = session.card.disconnect(pcsc::Disposition::LeaveCard);
            }
        }
        Ok(out)
    }

    fn select(&mut self) -> Result<(), TransportError> {
        // Try the full, spec-mandated AID first — some PIV implementations
        // (Nitrokey's `piv-authenticator`) only answer an exact-length AID
        // match and reject the short RID-only prefix `select()` sends. Fall
        // back to the short prefix only on a specific "not found", so a real
        // fault on the full-AID attempt still surfaces immediately rather
        // than being masked by a second, unrelated SELECT. See `piv::AID`'s
        // doc comment for the full story.
        let (data, sw) = self.transmit_full(&piv::select_full())?;
        if sw == piv::SW_NOT_FOUND {
            let (data, sw) = self.transmit_full(&piv::select())?;
            if sw == piv::SW_NOT_FOUND {
                self.select_response.clear();
                return Err(TransportError::NoPivApplet);
            }
            self.select_response = data;
            return ok_or_apdu("select piv applet (short aid)", sw);
        }
        self.select_response = data;
        ok_or_apdu("select piv applet", sw)
    }

    /// The connected card's raw ATR (contact) or PC/SC-synthesised
    /// pseudo-ATR (contactless), via `SCardStatus`. Empty on any transport
    /// failure — this backs a best-effort fingerprinting read (see
    /// [`Self::applet_fingerprint`]), not a precondition for anything else, so
    /// there is no error variant to plumb through.
    fn atr(&self) -> Vec<u8> {
        let mut names = [0u8; 256];
        let mut atr = [0u8; pcsc::MAX_ATR_SIZE];
        match self.card.status2(&mut names, &mut atr) {
            Ok(status) => status.atr().to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Resolve this session's [`keyroost_piv::fingerprint::AppletFingerprint`],
    /// the token's own name when one was actually discovered (see
    /// [`PivStatus::applet_name`]), its firmware version (see
    /// [`PivStatus::version_firmware`]), and — only for identities whose own
    /// probe supplies one — its serial number, so [`Self::status`] /
    /// [`Self::status_detailed`] can skip the Yubico GET SERIAL extension
    /// entirely when it would just get a fake answer (observed: a Nitrokey
    /// answers that extension too, with a serial that isn't its real one).
    /// The rest — from the ATR read just now plus the SELECT response
    /// captured by [`Self::select`]. When the select identity names
    /// OpenFIPS201, also probes for Swissbit's registered RID
    /// ([`keyroost_piv::fingerprint::wants_swissbit_probe`]); when neither
    /// that nor any text-based criterion fingerprints the applet at all, also
    /// probes [`keyroost_piv::fingerprint::FEITIAN_RID`]
    /// ([`Self::probe_feitian_rid`]) and, if that still leaves `Generic`,
    /// [`keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID`]
    /// ([`Self::probe_idprime_aid`]) as two last resorts, each cheaper to
    /// skip than to run, tried in that order before finally settling for
    /// `Generic`. Once the fingerprint itself is resolved, at most one
    /// further, fingerprint-specific step produces `applet_name`/version/
    /// serial: a Nitrokey (`Trussed(NitroKey)`) gets
    /// [`Self::probe_nitrokey_admin`] for its firmware, hardware variant, and
    /// serial; a YubiKey names itself from its own `GET VERSION` reply; and
    /// HID Crescendo (C2300 and C4000) names itself from its SELECT
    /// response's Application Label (already read above as
    /// `select_identity`) and, since neither family answers the Yubico
    /// extension at all, gets its *applet* version from its own GET PIV
    /// PROPERTIES response instead — see [`Self::hid_crescendo_version`]'s
    /// doc. Every probe here always re-selects PIV afterward so the session
    /// is left exactly as any other caller of [`Self::status`] expects,
    /// whether or not the probe itself succeeded.
    ///
    /// Returns `(fingerprint, name, version, version_firmware, serial)`:
    /// `version` fetches Yubico's own `GET VERSION` extension itself (no
    /// caller needs to pass one in — this is the sole place that issues it),
    /// except where a fingerprint's own probe supplies a better source
    /// instead (HID Crescendo — see above), in which case that replaces it;
    /// the two are never both meaningful for the same fingerprint, so there
    /// is nothing to merge, only to prefer, and this method does that
    /// itself rather than handing a caller two values to reconcile.
    /// `version_firmware` is the separate, genuinely-distinct-from-the-applet
    /// firmware version axis (currently Nitrokey only) — see
    /// [`PivStatus::version_firmware`]'s doc for why the two axes aren't
    /// interchangeable.
    fn applet_fingerprint(&mut self) -> AppletFingerprintResult {
        use keyroost_piv::fingerprint;

        let version = self.version();
        let atr = self.atr();
        let atr_identity =
            fingerprint::atr_historical_bytes(&atr).and_then(fingerprint::atr_identity);
        let select_identity = fingerprint::select_identity(&self.select_response);

        let swissbit_rid_selectable = fingerprint::wants_swissbit_probe(select_identity.as_deref())
            && self.probe_swissbit_rid();

        // `feitian_rid_selectable` and `idprime_aid_selectable` are each the
        // sole criterion for their own identity, so they're only worth their
        // own SELECT round trip when nothing else already fingerprints the
        // applet — check with both probe bits false first, and only run each
        // probe (then re-classify) when that still leaves `Generic`, Feitian
        // before IdPrime.
        let id = fingerprint::classify(
            atr_identity.as_deref(),
            select_identity.as_deref(),
            swissbit_rid_selectable,
            false,
            false,
        );
        let id = if id == fingerprint::AppletFingerprint::Generic {
            fingerprint::classify(
                atr_identity.as_deref(),
                select_identity.as_deref(),
                swissbit_rid_selectable,
                self.probe_feitian_rid(),
                false,
            )
        } else {
            id
        };
        let id = if id == fingerprint::AppletFingerprint::Generic {
            fingerprint::classify(
                atr_identity.as_deref(),
                select_identity.as_deref(),
                swissbit_rid_selectable,
                false,
                self.probe_idprime_aid(),
            )
        } else {
            id
        };
        // No generic name fallback here — an undiscovered name stays empty,
        // per `PivStatus::applet_name`'s doc; `id`/its `Display`/
        // `applet_name()` are the generic fallback for a caller that wants
        // one regardless.
        let (name, version, version_firmware, serial) = match id {
            fingerprint::AppletFingerprint::Trussed(fingerprint::TrussedVariant::NitroKey) => {
                let (name, firmware, serial) = self.probe_nitrokey_admin();
                (name, version, firmware, serial)
            }
            fingerprint::AppletFingerprint::YubiKey => {
                let name = version
                    .as_deref()
                    .and_then(fingerprint::format_yubikey_name);
                (name, version, None, None)
            }
            // HID Crescendo (either family — both are documented/observed to
            // answer a standard PIV SELECT, so there's no reason to expect
            // this to differ between them) names itself in its SELECT
            // response's Application Label (tag `0x50`) — already captured
            // above as `select_identity` (the same text `classify` matched
            // the generic `HidCrescendo` variant on, when the ATR didn't
            // already narrow it to a specific model): confirmed against a
            // live C2300 unit answering "HID Global ActivID Applet 3.0.3".
            // See <https://docs.hidglobal.com/crescendo/api/low-level/select.htm>
            // ("Data Field Returned in the Response Message for SELECT of
            // PIV Instance" — tag `0x50`, "Application Label"). It also
            // doesn't answer Yubico's own GET VERSION extension (`version`
            // above is always `None` for it), so its GET PIV PROPERTIES
            // response's own *applet* version block — HID's own
            // documentation names it "Applet Version Block" — is the only
            // applet-version source keyroost has for it, replacing the
            // empty Yubico reply as this fingerprint's `version`. Not
            // `version_firmware`: it's the same axis `version` represents
            // for any other fingerprint, just sourced differently, which is
            // also what `compat`'s `GetMetadata`/`Attest` C2300 known-
            // unsupported row is keyed on. See `Self::hid_crescendo_version`'s
            // doc.
            //
            // The Application Label already embeds a truncated copy of that
            // same version (the "3.0.3" tail above, versus GET PIV
            // PROPERTIES' fuller "3.0.3.6") — once the real version is known,
            // repeating a stale truncated one inside the name is just noise,
            // so it's stripped via
            // `fingerprint::strip_redundant_applet_version_suffix`.
            fingerprint::AppletFingerprint::HidCrescendo(
                variant @ (fingerprint::HidCrescendoVariant::C2300
                | fingerprint::HidCrescendoVariant::C4000),
            ) => {
                let hid_version = self.hid_crescendo_version(variant);
                let name = match (select_identity, &hid_version) {
                    (Some(name), Some(v)) => {
                        Some(fingerprint::strip_redundant_applet_version_suffix(&name, v))
                    }
                    (name, _) => name,
                };
                (name, hid_version, None, None)
            }
            _ => (None, version, None, None),
        };
        AppletFingerprintResult {
            fingerprint: id,
            name: name.unwrap_or_default(),
            version,
            version_firmware,
            serial,
        }
    }

    /// SELECT [`keyroost_piv::fingerprint::FEITIAN_RID`] and report whether the
    /// card accepted it, then unconditionally re-SELECT PIV afterward. Only
    /// called when nothing else already fingerprinted the applet — see the
    /// call site in [`Self::applet_fingerprint`] — since a Feitian RID match
    /// is the lowest-priority, catch-all criterion and every other one is
    /// cheaper to check first.
    fn probe_feitian_rid(&mut self) -> bool {
        let selectable = matches!(
            self.transmit_full(&piv::select_by_aid(&keyroost_piv::fingerprint::FEITIAN_RID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let _ = self.select();
        selectable
    }

    /// SELECT [`keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID`] and report whether
    /// the card accepted it — either the standard `SW = 9000`, or the
    /// non-standard `SW = 6999` this obscure applet instance is documented
    /// to also answer with — then unconditionally re-SELECT PIV afterward
    /// (mirrors [`Self::probe_feitian_rid`], against a full AID rather than a
    /// bare RID). Only called when nothing else, not even Feitian's own
    /// probe, already fingerprinted the applet — see the call site in
    /// [`Self::applet_fingerprint`].
    fn probe_idprime_aid(&mut self) -> bool {
        let selectable = matches!(
            self.transmit_full(&piv::select_by_aid(&keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID)),
            Ok((_, sw)) if sw == piv::SW_OK || sw == 0x6999
        );
        let _ = self.select();
        selectable
    }

    /// SELECT [`keyroost_piv::fingerprint::SWISSBIT_RID`] and report whether
    /// the card accepted it, then unconditionally re-SELECT PIV afterward
    /// (mirrors [`Self::probe_feitian_rid`], against Swissbit's registered
    /// RID). The re-select's own result is deliberately swallowed: a card
    /// that answered the PIV re-select badly here would have to fail the
    /// very next command this session issues anyway, with a clearer error at
    /// the point of use than anything this fingerprinting probe could add.
    fn probe_swissbit_rid(&mut self) -> bool {
        let selectable = matches!(
            self.transmit_full(&piv::select_by_aid(&keyroost_piv::fingerprint::SWISSBIT_RID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let _ = self.select();
        selectable
    }

    /// SELECT [`keyroost_piv::fingerprint::NITROKEY_ADMIN_AID`] (Trussed's admin
    /// application) and, if accepted, read the hardware variant via its
    /// `GET STATUS` management command
    /// ([`keyroost_piv::fingerprint::NITROKEY_GET_ADMIN_STATUS`], for
    /// `applet_name`), the firmware version via its `GET_VERSION` management
    /// command in string-output mode
    /// ([`keyroost_piv::fingerprint::NITROKEY_GET_VERSION_STRING`], split into
    /// byte components for [`PivStatus::version_firmware`]), and the device
    /// serial via [`keyroost_piv::fingerprint::NITROKEY_GET_SERIAL`] (its own
    /// 128-bit value, not the Yubico GET SERIAL extension a Nitrokey answers
    /// with an unrelated, made-up number) — then unconditionally re-SELECT
    /// PIV on every path (mirrors [`Self::probe_feitian_rid`] against yet
    /// another applet, but reading three commands' worth of reply instead of
    /// just the SELECT result). The three commands degrade independently:
    /// `(None, _, _)` when SELECT itself is refused (no admin application on
    /// this build) or the status command is refused/too short/names an
    /// unrecognised variant byte, `(_, None, _)` when the version command is
    /// refused, empty, or not a dotted-`u8` string, `(_, _, None)` when the
    /// serial command is refused or too long to fit a `u128` — either way, a
    /// Nitrokey that can't answer one of these simply reports nothing for
    /// that field rather than an error.
    fn probe_nitrokey_admin(&mut self) -> (Option<String>, Option<Vec<u8>>, Option<u128>) {
        use keyroost_piv::fingerprint;

        let selected = matches!(
            self.transmit_full(&piv::select_by_aid(&fingerprint::NITROKEY_ADMIN_AID)),
            Ok((_, sw)) if sw == piv::SW_OK
        );
        let (name, firmware, serial) = if selected {
            let name = self
                .transmit_full(&fingerprint::NITROKEY_GET_ADMIN_STATUS)
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| fingerprint::parse_nitrokey_variant(&data))
                .map(fingerprint::format_nitrokey_name);
            let firmware = self
                .transmit_full(&fingerprint::NITROKEY_GET_VERSION_STRING)
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| fingerprint::parse_ascii_text(&data))
                .and_then(|s| fingerprint::parse_dotted_version(&s));
            let serial = self
                .transmit_full(&fingerprint::NITROKEY_GET_SERIAL)
                .ok()
                .filter(|(_, sw)| *sw == piv::SW_OK)
                .and_then(|(data, _)| keyroost_piv::parse_serial(&data).ok());
            (name, firmware, serial)
        } else {
            (None, None, None)
        };
        let _ = self.select();
        (name, firmware, serial)
    }

    /// Read a read-only status snapshot: version, serial, PIN retries, CHUID,
    /// and which slots hold a certificate. No PIN, no touch.
    pub fn status(&mut self) -> Result<PivStatus, TransportError> {
        // Fingerprint resolution (which also resolves `version` — see
        // `Self::applet_fingerprint`'s doc) runs first: some identities' own
        // probes supply a real serial number, and when one does, the Yubico
        // GET SERIAL extension below is skipped entirely — a card that
        // answers it with a fake value (observed: a Nitrokey) never gets the
        // chance to overwrite the real one.
        let AppletFingerprintResult {
            fingerprint: applet_fingerprint,
            name: applet_name,
            version,
            version_firmware,
            serial: fingerprint_serial,
        } = self.applet_fingerprint();
        let serial = decode_serial_if_bcd(
            applet_fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
            fingerprint_serial.or_else(|| self.serial()),
        );
        let pin_retries = self.pin_retries();
        // Best-effort: a transport hiccup reading the CHUID shouldn't fail
        // the whole status snapshot, any more than an unsupported GET
        // VERSION/SERIAL does above.
        let chuid = self.read_chuid().unwrap_or_default();
        let mut slots = Vec::with_capacity(4);
        for slot in piv::Slot::all() {
            slots.push(self.slot_status(slot)?);
        }
        Ok(PivStatus {
            version,
            version_firmware,
            serial,
            pin_retries,
            slots,
            chuid,
            applet_fingerprint,
            applet_name,
        })
    }

    /// Resolve the per-fingerprint known-support table ([`keyroost_piv::compat`])
    /// for one of the vendor-extension operations this session exposes
    /// ([`Self::move_key`], [`Self::delete_key`]), from the applet's own
    /// fingerprint and reported version.
    ///
    /// Purely advisory: neither `move_key` nor `delete_key` version-gates
    /// itself any more (an unsupported card refuses the APDU on its own). A
    /// caller that wants to warn — or refuse — *before* the card sees the
    /// command calls this and acts on the [`FeatureGate`]. It runs the same
    /// fingerprint probes as [`Self::status`] and re-SELECTs PIV at the end,
    /// which clears any management-key authentication, so call it **before**
    /// [`Self::authenticate_management`].
    ///
    /// [`FeatureGate`]: keyroost_piv::compat::FeatureGate
    pub fn feature_gate(
        &mut self,
        feature: keyroost_piv::compat::PivExtension,
    ) -> keyroost_piv::compat::FeatureGate {
        let AppletFingerprintResult {
            fingerprint,
            version,
            version_firmware,
            ..
        } = self.applet_fingerprint();
        keyroost_piv::compat::resolve(
            feature,
            fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
        )
    }

    /// [`Self::status`] plus each slot's key algorithm, certificate Subject
    /// DN, and PIN/touch policy — the full per-slot view a status pane draws.
    ///
    /// The saving over calling `status()` and then `slot_key_algorithm` +
    /// `read_certificate` + `slot_policy` per slot is that each slot here
    /// costs exactly **one GET METADATA and one [`Self::read_certificate`]**
    /// (plus an ATTEST only as the pre-5.3-firmware policy fallback): that one
    /// certificate read feeds occupancy, the Subject DN, and the algorithm's
    /// step-3 fallback together, and the GET METADATA feeds both the algorithm
    /// and the policy. Calling the methods separately re-reads the certificate
    /// two or three times and GET METADATA twice, because [`PivSession`] holds
    /// no read cache.
    ///
    /// Algorithm and policy fall back exactly as [`Self::slot_key_algorithm`]
    /// and [`Self::slot_policy`] do (they share the resolvers), so a caller
    /// that generated a key in this session should [`Self::remember_pubkey`]
    /// it first to have that key named for a slot with no certificate yet.
    pub fn status_detailed(&mut self) -> Result<PivStatusDetailed, TransportError> {
        // See the identical ordering (and why) in `status`.
        let AppletFingerprintResult {
            fingerprint: applet_fingerprint,
            name: applet_name,
            version,
            version_firmware,
            serial: fingerprint_serial,
        } = self.applet_fingerprint();
        let serial = decode_serial_if_bcd(
            applet_fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
            fingerprint_serial.or_else(|| self.serial()),
        );
        let pin_retries = self.pin_retries();
        let chuid = self.read_chuid().unwrap_or_default();

        let mut slots = Vec::with_capacity(4);
        let mut detail = Vec::with_capacity(4);
        for slot in piv::Slot::all() {
            // The slot's one certificate read — its occupancy fields, its
            // Subject DN, and the algorithm's cert fallback all come off this.
            let cert = self.cert_object(slot)?;
            let cert_der = cert.as_ref().ok().and_then(Option::as_deref);
            // The slot's one GET METADATA — shared by algorithm and policy.
            let meta = self.metadata(slot.key_ref());

            let algorithm = self
                .algorithm_without_cert(slot, meta.as_ref())
                .or_else(|| self.hid_crescendo_slot_algorithm(slot))
                .or_else(|| {
                    cert_der
                        .and_then(|der| piv::x509_parse::parse_key_algorithm(der).ok().flatten())
                });
            let subject = cert_der
                .and_then(|der| piv::x509_parse::parse_subject_dn(der).ok())
                .map(|dn| dn.to_string());
            let policy = self.resolve_policy(slot, meta.as_ref());

            slots.push(slot_occupancy(
                slot,
                cert.as_ref().map(Option::as_deref).map_err(|e| *e),
            ));
            detail.push(PivSlotDetail {
                slot,
                algorithm,
                subject,
                policy,
            });
        }
        Ok(PivStatusDetailed {
            status: PivStatus {
                version,
                version_firmware,
                serial,
                pin_retries,
                slots,
                chuid,
                applet_fingerprint,
                applet_name,
            },
            slots: detail,
        })
    }

    /// Yubico's proprietary GET VERSION extension (`INS FD`), raw reply
    /// bytes, tolerant of any non-empty length — see [`PivStatus::version`]
    /// for why. `None` if the command errors, the card answers a non-`9000`
    /// status, or the reply is empty. [`Self::feature_gate`] passes the raw
    /// bytes straight to [`keyroost_piv::compat::resolve`], which compares
    /// them as a slice rather than requiring an exact 3-byte shape like real
    /// Yubico firmware's.
    fn version(&mut self) -> Option<Vec<u8>> {
        let (data, sw) = self.transmit_full(&piv::get_version()).ok()?;
        (sw == piv::SW_OK && !data.is_empty()).then_some(data)
    }

    /// Yubico GET SERIAL; `None` if unsupported (older firmware / non-Yubico).
    /// Widened to `u128` — see [`keyroost_piv::parse_serial`] for why the
    /// reply isn't always the standard 4-byte `u32`. Not called at all when
    /// [`Self::applet_fingerprint`] already produced a serial of its own —
    /// see the call sites in [`Self::status`]/[`Self::status_detailed`].
    fn serial(&mut self) -> Option<u128> {
        let (data, sw) = self.transmit_full(&piv::get_serial()).ok()?;
        if sw != piv::SW_OK {
            return None;
        }
        piv::parse_serial(&data).ok()
    }

    /// Remaining PIN tries via a no-op VERIFY. `63 Cx` → `Some(x)`, `6983`
    /// (blocked) → `Some(0)`, `9000` (already verified) / anything else → `None`.
    fn pin_retries(&mut self) -> Option<u8> {
        let (_, sw) = self.transmit_full(&piv::verify_pin_status()).ok()?;
        if let Some(n) = crate::sw_tries_remaining(sw) {
            Some(n)
        } else if sw == 0x6983 {
            Some(0)
        } else {
            None
        }
    }

    /// This session's [`keyroost_piv::fingerprint::AppletFingerprint`] plus
    /// its reported applet/firmware version bytes, resolved together once —
    /// via [`Self::version`] and [`Self::applet_fingerprint`], the same
    /// sources [`Self::status`] and [`Self::status_detailed`] use — and
    /// cached in [`Self::identity`] (the field) for the rest of the session;
    /// see that field's doc for why caching this particular resolution is
    /// safe. [`Self::fingerprint`], [`Self::quirks`], and
    /// [`Self::extension_gate`] are thin accessors over this.
    fn identity(&mut self) -> SessionIdentity {
        if let Some(identity) = &self.identity {
            return identity.clone();
        }
        let AppletFingerprintResult {
            fingerprint,
            version,
            version_firmware,
            ..
        } = self.applet_fingerprint();
        let identity = SessionIdentity {
            fingerprint,
            version,
            version_firmware,
        };
        self.identity = Some(identity.clone());
        identity
    }

    /// This session's [`keyroost_piv::fingerprint::AppletFingerprint`] — see
    /// [`Self::identity`]. Used by [`Self::hid_crescendo_slot_algorithm`] to
    /// find which HID Crescendo sub-variant (if any) it's talking to.
    fn fingerprint(&mut self) -> keyroost_piv::fingerprint::AppletFingerprint {
        self.identity().fingerprint
    }

    /// The [`keyroost_piv::compat::PivQuirk`]s active for this session's
    /// applet — see [`Self::identity`]. [`Self::metadata`] is the only
    /// caller today.
    fn quirks(&mut self) -> BTreeSet<keyroost_piv::compat::PivQuirk> {
        let SessionIdentity {
            fingerprint,
            version,
            version_firmware,
        } = self.identity();
        keyroost_piv::compat::resolve_quirks(
            fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
        )
    }

    /// The [`keyroost_piv::compat::FeatureGate`] for one of this session's
    /// *internally* consumed [`keyroost_piv::compat::PivExtension`]s
    /// ([`keyroost_piv::compat::PivExtension::GetMetadata`]/[`Attest`] —
    /// see [`Self::metadata`]/[`Self::attest`]) — see [`Self::identity`] for
    /// where the fingerprint/version data comes from. Distinct from the
    /// public [`Self::feature_gate`], which resolves the same way but always
    /// live (never cached) for the UI-facing extensions
    /// ([`MoveKey`](keyroost_piv::compat::PivExtension::MoveKey)/
    /// [`DeleteKey`](keyroost_piv::compat::PivExtension::DeleteKey)) — a
    /// caller of that one relies on the live re-SELECT it performs as a side
    /// effect (see its doc), which caching here would silently drop after
    /// the first call.
    fn extension_gate(
        &mut self,
        extension: keyroost_piv::compat::PivExtension,
    ) -> keyroost_piv::compat::FeatureGate {
        let SessionIdentity {
            fingerprint,
            version,
            version_firmware,
        } = self.identity();
        keyroost_piv::compat::resolve(
            extension,
            fingerprint,
            version.as_deref(),
            version_firmware.as_deref(),
        )
    }

    /// GET METADATA for a key/PIN reference (`0x9B`, `0x80`, `0x81`, or a slot
    /// key ref). `None` when the firmware predates the extension (5.3-), or
    /// this fingerprint/version is known to never answer it at all
    /// ([`keyroost_piv::compat::PivExtension::GetMetadata`] resolving
    /// [`keyroost_piv::compat::FeatureGate::Unsupported`] — the HID
    /// Crescendo C2300 family at its observed GET PIV PROPERTIES version) —
    /// checked *before* sending anything, so this never puts the unsupported
    /// extension APDU on the wire for those devices at all, unlike
    /// [`keyroost_piv::compat::PivQuirk::InsF7MetadataAlgorithmInvalid`]
    /// below, which needs the reply in hand to know what to strip from it.
    ///
    /// Runs [`clear_metadata_if_quirky`] over the parsed reply before
    /// returning it — see that function's doc for what it strips and why.
    /// This is the sole place that needs to know about either check: every
    /// caller of [`Self::metadata`] — [`Self::slot_key`]/
    /// [`metadata_key_material`], [`Self::algorithm_without_cert`],
    /// [`Self::resolve_policy`], [`Self::reported_management_key_algorithm`],
    /// [`Self::status_detailed`] — already treats a missing algorithm/public
    /// key as "fall back to another source", which is exactly the right
    /// behavior on a device where GET METADATA can't be trusted, or isn't
    /// there at all.
    pub fn metadata(&mut self, key_ref: u8) -> Option<Metadata> {
        if self.extension_gate(keyroost_piv::compat::PivExtension::GetMetadata)
            == keyroost_piv::compat::FeatureGate::Unsupported
        {
            return None;
        }
        let (data, sw) = self.transmit_full(&piv::get_metadata(key_ref)).ok()?;
        if sw != piv::SW_OK {
            return None;
        }
        let md = piv::parse_metadata(&data).ok()?;
        Some(clear_metadata_if_quirky(&self.quirks(), md))
    }

    /// The raw response body of a HID Crescendo GET PIV PROPERTIES read for
    /// `variant` (must be [`HidCrescendoVariant::C2300`] or
    /// [`HidCrescendoVariant::C4000`] — the two families this crate knows a
    /// request for; [`HidCrescendoVariant::Generic`] sends nothing and
    /// yields an empty read, since keyroost has no confirmed request shape
    /// for an unidentified HID Crescendo model), cached once per session —
    /// see [`Self::hid_crescendo_properties_raw`] (the field) for why this
    /// is the single fetch both [`Self::hid_crescendo_slot_key_algorithms`] (the
    /// per-slot algorithm list) and [`Self::hid_crescendo_version`] (this
    /// applet's own version, consulted by [`Self::applet_fingerprint`])
    /// derive from, rather than each issuing its own read.
    ///
    /// `variant` is a parameter rather than resolved internally via
    /// [`Self::fingerprint`] on purpose: [`Self::applet_fingerprint`] (via
    /// [`Self::identity`]) is what determines the fingerprint in the first
    /// place, and its own HID Crescendo branch is a caller of this method —
    /// calling back into [`Self::fingerprint`]/[`Self::identity`] from here
    /// would recurse into a resolution that hasn't finished yet. Every
    /// caller already has the variant in hand from its own match on
    /// [`keyroost_piv::fingerprint::AppletFingerprint`].
    ///
    /// Issues the read on first call; every later call in the same session
    /// reuses the cache regardless of which `variant` is passed (a session's
    /// fingerprint can't change mid-connection, so this is never asked for
    /// two different variants in the same session). A read that errors or
    /// answers a non-`9000` status caches as an empty `Vec` — both derived
    /// parses already treat that the same as "nothing to report".
    fn hid_crescendo_properties_raw(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> Vec<u8> {
        use keyroost_piv::fingerprint::{self, HidCrescendoVariant};

        if let Some(raw) = &self.hid_crescendo_properties_raw {
            return raw.clone();
        }
        let apdu = match variant {
            HidCrescendoVariant::C2300 => Some(piv::get_data(
                &fingerprint::HID_CRESCENDO_C2300_PROPERTIES_TAG,
            )),
            HidCrescendoVariant::C4000 => {
                Some(fingerprint::HID_CRESCENDO_C4000_GET_PROPERTIES.to_vec())
            }
            // `Generic` (no confirmed request shape) and any future variant
            // this crate doesn't know a GET PIV PROPERTIES request for yet.
            _ => None,
        };
        let raw = apdu
            .and_then(|apdu| self.transmit_full(&apdu).ok())
            .filter(|(_, sw)| *sw == piv::SW_OK)
            .map(|(data, _)| data)
            .unwrap_or_default();
        self.hid_crescendo_properties_raw = Some(raw.clone());
        raw
    }

    /// This session's parsed `(key_ref, algorithm_id)` pairs from a HID
    /// Crescendo GET PIV PROPERTIES read, one pair per slot that actually
    /// has a key loaded (a slot whose PKI container exists but reports no
    /// key generated/injected is excluded — see
    /// [`keyroost_piv::fingerprint::parse_hid_crescendo_slot_key_algorithms`]'s doc)
    /// — see [`Self::hid_crescendo_properties_raw`] for the shared,
    /// once-per-session fetch this derives from. An empty list either way a
    /// read can come up empty: the read itself failing, or a well-formed
    /// response simply naming no slot with a key loaded.
    fn hid_crescendo_slot_key_algorithms(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> Vec<(u8, u8)> {
        let raw = self.hid_crescendo_properties_raw(variant);
        keyroost_piv::fingerprint::parse_hid_crescendo_slot_key_algorithms(&raw)
    }

    /// This applet's own version, from the same HID Crescendo GET PIV
    /// PROPERTIES read [`Self::hid_crescendo_slot_key_algorithms`] uses — see
    /// [`Self::hid_crescendo_properties_raw`]. [`Self::applet_fingerprint`]
    /// feeds this into the "firmware version" axis
    /// [`keyroost_piv::compat::resolve`]/[`keyroost_piv::compat::resolve_quirks`]
    /// compare against [`keyroost_piv::compat::PivExtension::GetMetadata`]/
    /// [`Attest`](keyroost_piv::compat::PivExtension::Attest)'s HID-specific
    /// known-unsupported row, since this fingerprint never answers Yubico's
    /// own GET VERSION extension the applet axis elsewhere keys on. `None`
    /// when the read fails or doesn't carry a version block.
    fn hid_crescendo_version(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> Option<Vec<u8>> {
        let raw = self.hid_crescendo_properties_raw(variant);
        keyroost_piv::fingerprint::parse_hid_crescendo_version(&raw)
    }

    /// Whether this HID Crescendo's GET PIV PROPERTIES read names the PIV
    /// management key (`0x9B`) as a real slot object at all — see
    /// [`keyroost_piv::fingerprint::hid_crescendo_reports_slot`]'s doc. The
    /// sole consumer, [`Self::authenticate_management`], uses this to decide
    /// between the standard `0x9B` `GENERAL AUTHENTICATE` round (most PIV
    /// applets, and the minority of HID Crescendo units HID's own Crescendo
    /// Manager documentation says do expose `0x9B`:
    /// <https://docs.hidglobal.com/crescendo-manager/CM/about-cm.htm>) and
    /// the vendor ACA XAUTH fallback (most HID Crescendo units, including
    /// every unit this crate has actually been tested against).
    fn hid_crescendo_reports_management_key(
        &mut self,
        variant: keyroost_piv::fingerprint::HidCrescendoVariant,
    ) -> bool {
        let raw = self.hid_crescendo_properties_raw(variant);
        keyroost_piv::fingerprint::hid_crescendo_reports_slot(&raw, piv::KEY_REF_MANAGEMENT)
    }

    /// HID Crescendo's substitute for GET METADATA's algorithm field: this
    /// fingerprint/version resolves
    /// [`keyroost_piv::compat::PivExtension::GetMetadata`] to
    /// [`keyroost_piv::compat::FeatureGate::Unsupported`] (see
    /// [`Self::metadata`]'s doc — today only confirmed for C2300, but C4000
    /// exposes the same GET PIV PROPERTIES data too), so this reads the
    /// vendor's own data object instead via [`Self::hid_crescendo_slot_key_algorithms`].
    /// `None` on any other fingerprint (nothing to try), or when the read
    /// doesn't name `slot`'s key at all.
    fn hid_crescendo_slot_algorithm(&mut self, slot: Slot) -> Option<KeyAlg> {
        let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        else {
            return None;
        };
        let key_ref = slot.key_ref();
        let id = self
            .hid_crescendo_slot_key_algorithms(variant)
            .into_iter()
            .find(|&(kr, _)| kr == key_ref)?
            .1;
        keyroost_piv::fingerprint::hid_crescendo_algorithm_from_id(id)
    }

    /// The card-management (9B) key's algorithm *as the card reports it* via
    /// GET METADATA, or `None` when the card doesn't answer the extension
    /// (pre-5.3 YubiKey firmware, and non-Yubico applets that stub it out).
    /// It makes no assumption about what an absent answer means — see
    /// [`Self::resolve_management_key_algorithm`].
    pub fn reported_management_key_algorithm(&mut self) -> Option<MgmtAlg> {
        self.metadata(piv::KEY_REF_MANAGEMENT)
            .and_then(|m| m.algorithm)
            .and_then(MgmtAlg::from_id)
    }

    /// Decide which algorithm to run management-key authentication under, given
    /// the length of the key the caller holds.
    ///
    /// 1. If GET METADATA reports an algorithm, that wins (its expected key
    ///    length is checked against `key_len`).
    /// 2. Otherwise, probe **every** algorithm — regardless of `key_len` — with
    ///    GENERAL AUTHENTICATE step 1 (request witness only; no key-derived
    ///    material reaches the card) and collect the ones the card accepts with
    ///    `SW 9000`. Then:
    ///    * narrow that accepted set to the algorithms whose key is `key_len`
    ///      bytes;
    ///    * if one remains, use it;
    ///    * if several remain and 3DES is among them, use 3DES (the historical
    ///      pre-metadata default — only 3DES and AES-192 can collide on length);
    ///    * if the card accepted nothing, fall back to `key_len` alone.
    ///
    /// The chosen algorithm is only *returned*; the caller still runs
    /// [`Self::authenticate_management`] with it to actually authenticate.
    ///
    /// Returns [`TransportError::PivBadKeyLength`] when nothing the card
    /// accepts (or, on an empty probe, no algorithm at all) matches `key_len`.
    pub fn resolve_management_key_algorithm(
        &mut self,
        key_len: usize,
    ) -> Result<MgmtAlg, TransportError> {
        if let Some(alg) = self.reported_management_key_algorithm() {
            if alg.key_len() != key_len {
                return Err(TransportError::PivBadKeyLength);
            }
            return Ok(alg);
        }

        // No GET METADATA. Probe each algorithm's GENERAL AUTHENTICATE P1 with a
        // bare witness request and see which the card is willing to start.
        const ALL: [MgmtAlg; 4] = [
            MgmtAlg::TripleDes,
            MgmtAlg::Aes128,
            MgmtAlg::Aes192,
            MgmtAlg::Aes256,
        ];
        trace::line(self.debug, || {
            "piv mgmt-key: GET METADATA unsupported; probing every GENERAL \
             AUTHENTICATE P1 with a witness request"
                .to_string()
        });
        let mut accepted: Vec<MgmtAlg> = Vec::with_capacity(ALL.len());
        for alg in ALL {
            // A transport failure (card pulled, reader gone) is fatal for every
            // candidate — propagate it rather than mislabel it "bad key
            // length". Only a non-9000 status word means "not this P1".
            let (_, sw) = self.transmit_full(&piv::general_auth_request_witness(
                alg,
                piv::KEY_REF_MANAGEMENT,
            ))?;
            let ok = sw == piv::SW_OK;
            trace::line(self.debug, || {
                format!(
                    "piv mgmt-key: probe {} (P1={:#04x}) -> {}",
                    alg.label(),
                    alg.id(),
                    if ok {
                        "accepted".to_string()
                    } else {
                        format!("rejected (SW {sw:04X})")
                    }
                )
            });
            if ok {
                accepted.push(alg);
            }
        }

        if accepted.is_empty() {
            trace::line(self.debug, || {
                "piv mgmt-key: card accepted no probe; falling back to key length".to_string()
            });
        }
        let chosen = pick_mgmt_alg(&accepted, key_len).ok_or(TransportError::PivBadKeyLength)?;
        trace::line(self.debug, || {
            format!("piv mgmt-key: selected {}", chosen.label())
        });
        Ok(chosen)
    }

    /// Authenticate to unlock PIV admin operations (key generation,
    /// certificate import, set-management-key, set-pin-retries). `alg` must
    /// match the card's stored management-key algorithm (see
    /// [`Self::resolve_management_key_algorithm`]) on the standard path below; the
    /// HID Crescendo ACA path further down instead reads the real algorithm
    /// off the card at auth time, so `alg` only bounds the initial
    /// key-length check there.
    ///
    /// Two mechanisms, picked per fingerprint and per device:
    ///
    /// 1. **Standard PIV** — every applet except HID Crescendo, plus the
    ///    minority of HID Crescendo units that *do* expose the management
    ///    key (`0x9B`) as a real slot object (HID's own Crescendo Manager
    ///    documentation: <https://docs.hidglobal.com/crescendo-manager/CM/about-cm.htm>
    ///    — see [`Self::hid_crescendo_reports_management_key`]): the
    ///    GENERAL AUTHENTICATE witness/challenge round below, unchanged
    ///    from before this method knew HID Crescendo existed.
    /// 2. **HID Crescendo ACA XAUTH** — every other HID Crescendo unit (the
    ///    majority; every unit this crate has actually been tested against),
    ///    which doesn't model `0x9B` as a PIV object at all (confirmed on a
    ///    live C2300 unit: `SW = 6D 00` to a standard GENERAL AUTHENTICATE on
    ///    `0x9B`), so the standard round has nothing to authenticate
    ///    against. Delegates to
    ///    [`Self::authenticate_management_hid_crescendo_aca`] — see its doc
    ///    for the sequence and for why switching back to PIV at the end
    ///    doesn't throw the resulting authentication away the way it would
    ///    for the standard mechanism.
    ///
    /// Neither path implements HID Crescendo's separate PIN-only unlock for
    /// most management operations (documented e.g. at
    /// <https://docs.hidglobal.com/hid-crescendo-sdk-v1.2/API%20references/html/md_Documentation_204_8EXAMPLES.html>).
    /// That's a different mechanism from Yubico's own PIN-unlock extension,
    /// which retrieves the actual management key via the PIN and then still
    /// runs the standard round below — and Yubico's own version isn't
    /// implemented here either yet, so HID Crescendo's is left out for the
    /// same reason, not a HID-specific gap.
    pub fn authenticate_management(
        &mut self,
        alg: MgmtAlg,
        key: &[u8],
    ) -> Result<(), TransportError> {
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }

        if let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        {
            if !self.hid_crescendo_reports_management_key(variant) {
                return self.authenticate_management_hid_crescendo_aca(key);
            }
        }

        // Step 1: ask the card for an encrypted witness.
        let (resp, sw) = self.transmit_full(&piv::general_auth_request_witness(
            alg,
            piv::KEY_REF_MANAGEMENT,
        ))?;
        ok_or_apdu("piv authenticate (request witness)", sw)?;
        let z1 = piv::parse_general_auth(&resp, 0x80).map_err(TransportError::PivParse)?;
        // Decrypt it with the management key — proves we hold the key.
        let witness = Zeroizing::new(block_crypt(alg, key, z1, CryptOp::Decrypt)?);

        // Step 2: return the decrypted witness plus our own random challenge.
        let mut challenge = vec![0u8; alg.block_size()];
        getrandom::getrandom(&mut challenge).map_err(|_| TransportError::HostRngFailed)?;
        let apdu = Zeroizing::new(piv::general_auth_mutual(
            alg,
            piv::KEY_REF_MANAGEMENT,
            &witness,
            &challenge,
        ));
        let (resp2, sw2) = self.transmit_full(&apdu)?;
        // A wrong key makes the card reject our witness here.
        if sw2 != piv::SW_OK {
            return Err(TransportError::PivManagementAuthFailed);
        }
        // Some cards (observed: Identiv uTrust FIDO2 Security Key) answer this
        // step with `SW_OK` and an empty body instead of a `7C` template
        // carrying the encrypted-challenge tag `0x82` — they verify our
        // witness (a wrong one is rejected with a non-success status, same as
        // above) but never implement the card-to-host half of mutual auth.
        //
        // This is NIST SP 800-73's "client (application) authentication" —
        // only the client proves possession of the management key — versus
        // the fuller "mutual authentication" that also has the card prove
        // itself back to the client via 0x82. Client auth is the half that
        // actually gates PIV admin operations, so it's sufficient on its own;
        // we still *request* the mutual exchange up front (same step-1 APDU,
        // same 0x80+0x81 step-2 APDU either way) because it's a strict
        // superset — cards that only implement client auth answer exactly as
        // they do here, and cards that implement the full round give us extra
        // assurance, before writing new key material, that the "OK" we got
        // back came from something that actually holds the key rather than a
        // card that blindly answers success. So: treat this as authenticated
        // rather than erroring on an 0x82 template that was never coming.
        if resp2.is_empty() {
            // Say so in the trace: the assurance on this card is one-sided,
            // and a reviewer (or a user wondering why a swapped card was
            // accepted) should be able to see that the weaker path was taken.
            trace::line(self.debug, || {
                "! piv authenticate: card returned no 0x82 challenge response; \
                 accepting host-only (client) authentication — this card cannot \
                 prove it holds the management key"
                    .to_string()
            });
            return Ok(());
        }
        // Verify the card encrypted our challenge correctly (authenticates the
        // card to us, completing mutual auth). Constant-time out of principle —
        // both sides are fresh per attempt, so the timing leaks nothing useful,
        // but secret-adjacent comparisons shouldn't short-circuit.
        let z2 = piv::parse_general_auth(&resp2, 0x82).map_err(TransportError::PivParse)?;
        let expected = Zeroizing::new(block_crypt(alg, key, &challenge, CryptOp::Encrypt)?);
        if !ct_eq(z2, &expected) {
            return Err(TransportError::PivManagementAuthFailed);
        }
        Ok(())
    }

    /// The vendor fallback [`Self::authenticate_management`] uses for a HID
    /// Crescendo unit whose GET PIV PROPERTIES read doesn't name the PIV
    /// management key (`0x9B`) as a real slot object (see
    /// [`Self::hid_crescendo_reports_management_key`]) — HID's External
    /// Authentication sequence against the ACA (Access Control Applet)
    /// instance's XAUTH key 1:
    /// <https://docs.hidglobal.com/crescendo/api/low-level/external-auth-xauth.htm>.
    ///
    /// 1. Temporarily SELECT the ACA instance
    ///    ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`]).
    /// 2. GET CHALLENGE, and read XAUTH key 1's algorithm off the response's
    ///    own length
    ///    ([`keyroost_piv::fingerprint::hid_crescendo_xauth_key_alg`]) — the
    ///    ground truth for what this specific card's XAUTH key actually is,
    ///    regardless of what [`Self::authenticate_management`]'s caller
    ///    believed when it chose the `alg` it was called with (typically a
    ///    length-only guess here, since a card that reaches this path has
    ///    already been established not to answer GET METADATA on `0x9B` —
    ///    there's nothing on this path *to* report). `key`'s length must
    ///    match this algorithm, independent of the caller's `alg`.
    /// 3. EXTERNAL AUTHENTICATE, `key` block-encrypting the challenge
    ///    (single-block, ECB-style — the same primitive [`block_crypt`]
    ///    already runs for standard PIV management-key auth).
    /// 4. Unconditionally re-SELECT PIV, success or failure — same
    ///    discipline as every other temporary-SELECT probe in this file
    ///    (e.g. [`Self::probe_swissbit_rid`]). Unlike those probes, though,
    ///    this re-select isn't discarding anything: per NIST GSC-IS 2.1's
    ///    access-condition model, the ACA's "External Authentication"
    ///    access condition, once satisfied, is a *card-wide* grant rather
    ///    than one scoped to the ACA instance — see
    ///    [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`]'s doc — so
    ///    the PIV applet is left authenticated for the same admin
    ///    operations the standard `0x9B` round would have unlocked. Callers
    ///    still need to run this (or the standard round) immediately before
    ///    the admin operation it gates, same as always: any *later*
    ///    re-select — including this method's own step 1 SELECT, on a
    ///    second call — clears it again.
    fn authenticate_management_hid_crescendo_aca(
        &mut self,
        key: &[u8],
    ) -> Result<(), TransportError> {
        use keyroost_piv::fingerprint;

        let result: Result<(), TransportError> = (|| {
            let (_, sw) =
                self.transmit_full(&piv::select_by_aid(&fingerprint::HID_CRESCENDO_ACA_AID))?;
            ok_or_apdu("piv aca select", sw)?;
            self.aca_xauth_unlock(key)
        })();

        // Step 4: always switch back to PIV — see this method's doc.
        let _ = self.select();
        result
    }

    /// Steps 2–3 of the External Authentication sequence
    /// [`Self::authenticate_management_hid_crescendo_aca`]'s doc describes:
    /// GET CHALLENGE, then EXTERNAL AUTHENTICATE with `key` block-encrypting
    /// that challenge. Factored out (unlike that method) so
    /// [`Self::hid_crescendo_aca_put_xauth_key_op`] can run the same
    /// unlock immediately before PUT XAUTH KEY *without* an intervening
    /// re-SELECT back to PIV and forward to ACA again — the caller is
    /// responsible for having already SELECTed
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`], and for
    /// switching back to PIV afterward, same discipline as every other
    /// temporary-SELECT probe in this file.
    fn aca_xauth_unlock(&mut self, key: &[u8]) -> Result<(), TransportError> {
        use keyroost_piv::fingerprint;

        let (challenge, sw) = self.transmit_full(&fingerprint::HID_CRESCENDO_ACA_GET_CHALLENGE)?;
        ok_or_apdu("piv aca get challenge", sw)?;
        let alg = fingerprint::hid_crescendo_xauth_key_alg(challenge.len())
            .ok_or(TransportError::PivBadKeyLength)?;
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }

        let cryptogram = Zeroizing::new(block_crypt(alg, key, &challenge, CryptOp::Encrypt)?);
        let apdu = Zeroizing::new(fingerprint::hid_crescendo_aca_external_authenticate(
            &cryptogram,
        ));
        let (_, sw) = self.transmit_full(&apdu)?;
        if sw != piv::SW_OK {
            // Per HID's documentation, `SW = 6A 88` ("XAUTH 1 key has
            // not been initialized"), `SW = 69 85` ("Get Challenge not
            // sent before this command" — can't happen here, since the
            // GET CHALLENGE above always runs first), and `SW = 63 00`
            // ("invalid cryptogram") are all distinguished from success;
            // none gets special handling — they all just mean
            // "authentication did not succeed" — but the raw status
            // word still reaches `--debug` output here, for whoever's
            // diagnosing a real device against this.
            trace::line(self.debug, || {
                format!("piv aca external authenticate: rejected (SW {sw:04X})")
            });
            return Err(TransportError::PivManagementAuthFailed);
        }
        Ok(())
    }

    /// Present the PIV application PIN. Required before private-key use and
    /// set-pin-retries. The PIN must be 6–8 bytes — the byte layer returns a
    /// typed error on anything else rather than pad/truncate, so an unchecked
    /// over-length PIN can never silently verify (and store) something other
    /// than what the user typed, and no retry counter is consumed.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let apdu =
            Zeroizing::new(piv::verify_pin(pin).map_err(|_| TransportError::PivBadPinLength)?);
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// [`Self::verify_pin`], but against HID Crescendo's ACA (Access Control
    /// Applet) instance's own VERIFY PIN reference
    /// ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_REF`], `P2 = 0x00`)
    /// instead of the standard PIV application-PIN reference
    /// (`PIN_REF_APPLICATION`, `P2 = 0x80`) [`Self::verify_pin`] always uses.
    /// Callers must have already SELECTed
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`] — sending the
    /// standard reference while ACA is selected is not this command, and
    /// sending this one while PIV is selected wouldn't be either.
    /// [`Self::hid_crescendo_aca_put_xauth_key_op`]'s `Pin` branch is the
    /// sole caller.
    fn verify_pin_hid_crescendo_aca(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::verify_pin_at(keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_REF, pin)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Unlock PIV management via
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`] instead of
    /// the standard `0x9B` management-key round: [`Self::verify_pin`], then —
    /// only if this fingerprint carries
    /// [`keyroost_piv::compat::PivQuirk::PinManagementAuthProtected9BKey`] —
    /// read the PIN-protected management key
    /// ([`keyroost_piv::OBJECT_PIN_PROTECTED_DATA`],
    /// [`keyroost_piv::parse_pin_protected_management_key`]) and run
    /// [`Self::authenticate_management`] with it, exactly as if the user had
    /// typed that key directly. A device without the quirk needs nothing
    /// past the PIN VERIFY — management is unlocked directly, the same way
    /// HID Crescendo does it.
    ///
    /// Callers should check
    /// [`keyroost_piv::compat::PivExtension::PinManagementAuth`] via
    /// [`Self::feature_gate`] before offering this at all; this method itself
    /// doesn't gate on it — a PIN VERIFY that the card accepts is taken as
    /// license to try, on the same "let the card refuse it" principle
    /// [`Self::authenticate_management`]'s own callers already follow for
    /// MOVE KEY/DELETE KEY.
    ///
    /// Errors: whatever [`Self::verify_pin`] returns for a wrong/blocked PIN;
    /// [`TransportError::PivPinProtectedKeyNotSet`] if the quirk applies and
    /// no management key comes back from the read (the read failed, or
    /// succeeded with no tag `0x88` / subtag `0x89` — PIN management auth was
    /// never set up on this card); otherwise whatever
    /// [`Self::authenticate_management`] returns for the retrieved key.
    pub fn authenticate_management_via_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        self.verify_pin(pin)?;
        if !self
            .quirks()
            .contains(&keyroost_piv::compat::PivQuirk::PinManagementAuthProtected9BKey)
        {
            return Ok(());
        }
        let (data, sw) =
            self.transmit_full(&piv::get_data(&keyroost_piv::OBJECT_PIN_PROTECTED_DATA))?;
        if sw != piv::SW_OK {
            return Err(TransportError::PivPinProtectedKeyNotSet);
        }
        let key = keyroost_piv::parse_pin_protected_management_key(&data)
            .ok_or(TransportError::PivPinProtectedKeyNotSet)?;
        let alg = self.resolve_management_key_algorithm(key.len())?;
        self.authenticate_management(alg, &key)
    }

    /// Change the PIV PIN. A wrong `old` PIN consumes a try and reports the
    /// remaining count. Both PINs must be 6–8 bytes.
    pub fn change_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::change_reference(piv::PIN_REF_APPLICATION, old, new)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Change the PUK. A wrong `old` PUK consumes a try and reports the count.
    /// Both PUKs must be 6–8 bytes.
    pub fn change_puk(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::change_reference(piv::PIN_REF_PUK, old, new)
                .map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Unblock a blocked PIN using the PUK, setting a new PIN. A wrong PUK
    /// consumes a try and reports the remaining count. Both must be 6–8 bytes.
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            piv::unblock_pin(puk, new_pin).map_err(|_| TransportError::PivBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Set the PIN and PUK retry counts (resetting both to their defaults).
    /// Requires prior management-key auth **and** a verified PIN.
    pub fn set_pin_retries(&mut self, pin_tries: u8, puk_tries: u8) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::set_pin_retries(pin_tries, puk_tries))?;
        ok_or_write("piv set pin retries", sw)
    }

    /// Replace the card-management key with `(alg, key)`. Requires prior
    /// management-key auth ([`Self::authenticate_management`] /
    /// [`Self::authenticate_management_via_pin`]) — **except** on a HID
    /// Crescendo unit whose GET PIV PROPERTIES read doesn't name `0x9B` as a
    /// real slot object (see [`Self::hid_crescendo_reports_management_key`]):
    /// there, the "management key" is the ACA's XAUTH key 1, not a real PIV
    /// object, changed with HID's own PUT XAUTH KEY command instead of the
    /// standard SET MANAGEMENT KEY extension — see
    /// [`Self::hid_crescendo_aca_put_xauth_key_op`] for that path, which
    /// takes `current` to run its own self-contained unlock rather than
    /// relying on a prior call's access condition still being in force.
    /// Every other fingerprint ignores `current` entirely.
    pub fn set_management_key(
        &mut self,
        current: CurrentMgmtAuth<'_>,
        alg: MgmtAlg,
        key: &[u8],
        require_touch: bool,
    ) -> Result<(), TransportError> {
        if key.len() != alg.key_len() {
            return Err(TransportError::PivBadKeyLength);
        }
        if let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        {
            if !self.hid_crescendo_reports_management_key(variant) {
                return self.hid_crescendo_aca_put_xauth_key_op(
                    current,
                    HidCrescendoXauthKeyOp::Set(alg, key),
                );
            }
        }
        let apdu = Zeroizing::new(piv::set_management_key(alg, key, require_touch));
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("piv set management key", sw)
    }

    /// Delete HID Crescendo's ACA XAUTH key 1 outright, rather than
    /// replacing it — the "Delete" option in the management-key rotation UI,
    /// offered only when [`Self::fingerprint`] resolves to
    /// [`keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo`] with no
    /// real `0x9B` slot object (see
    /// [`Self::hid_crescendo_reports_management_key`]) — every other applet
    /// has no equivalent operation, since a standard PIV management key is
    /// mandatory and can only be *replaced*, never removed. Returns
    /// [`TransportError::PivManagementKeyDeleteUnsupported`] if `self` isn't
    /// that specific device; a caller that only offers this option when
    /// [`Self::fingerprint`] already says so should never actually hit that
    /// error unless the card was swapped mid-flow.
    ///
    /// Runs the same select/unlock/reselect sequence
    /// [`Self::hid_crescendo_aca_put_xauth_key_op`] documents, with
    /// [`HidCrescendoXauthKeyOp::Delete`] in place of `Set`.
    pub fn delete_management_key_hid_crescendo(
        &mut self,
        current: CurrentMgmtAuth<'_>,
    ) -> Result<(), TransportError> {
        let keyroost_piv::fingerprint::AppletFingerprint::HidCrescendo(variant) =
            self.fingerprint()
        else {
            return Err(TransportError::PivManagementKeyDeleteUnsupported);
        };
        if self.hid_crescendo_reports_management_key(variant) {
            return Err(TransportError::PivManagementKeyDeleteUnsupported);
        }
        self.hid_crescendo_aca_put_xauth_key_op(current, HidCrescendoXauthKeyOp::Delete)
    }

    /// The vendor fallback [`Self::set_management_key`]/
    /// [`Self::delete_management_key_hid_crescendo`] use for a HID Crescendo
    /// unit that doesn't model the PIV management key (`0x9B`) as a real slot
    /// object (see [`Self::hid_crescendo_reports_management_key`]): PUT XAUTH
    /// KEY against the ACA (Access Control Applet) instance's XAUTH key 1,
    /// per the user-provided sequence:
    ///
    /// 1. Temporarily SELECT the ACA instance
    ///    ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`]).
    /// 2. Unlock: [`Self::verify_pin_hid_crescendo_aca`] for
    ///    [`CurrentMgmtAuth::Pin`] — **not** [`Self::verify_pin`], which
    ///    uses the standard PIV application-PIN reference rather than the
    ///    one ACA's own VERIFY PIN answers at — or
    ///    [`Self::aca_xauth_unlock`] (the same GET CHALLENGE / EXTERNAL
    ///    AUTHENTICATE round [`Self::authenticate_management_hid_crescendo_aca`]
    ///    runs) for [`CurrentMgmtAuth::Key`] — this method's own unlock,
    ///    run fresh rather than assumed still in force from an earlier
    ///    [`Self::authenticate_management`] /
    ///    [`Self::authenticate_management_via_pin`] call, since installing or
    ///    deleting a XAUTH key happens on the ACA instance itself and this
    ///    method has no way to know whether an unlock elsewhere actually
    ///    persisted this far.
    /// 3. [`HidCrescendoXauthKeyOp::Set`] runs
    ///    [`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key`] with
    ///    the new `(alg, key)` — `alg` must be
    ///    [`MgmtAlg::TripleDes`]/[`MgmtAlg::Aes128`] — the only two
    ///    algorithms ACA XAUTH supports —
    ///    [`TransportError::PivBadKeyLength`] for anything else, same error
    ///    the length mismatch in [`Self::set_management_key`] already uses.
    ///    [`HidCrescendoXauthKeyOp::Delete`] runs
    ///    [`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove`]
    ///    instead, unconditionally.
    /// 4. Unconditionally re-SELECT PIV, success or failure — same
    ///    discipline as [`Self::authenticate_management_hid_crescendo_aca`]
    ///    and every other temporary-SELECT probe in this file.
    fn hid_crescendo_aca_put_xauth_key_op(
        &mut self,
        current: CurrentMgmtAuth<'_>,
        op: HidCrescendoXauthKeyOp<'_>,
    ) -> Result<(), TransportError> {
        use keyroost_piv::fingerprint;

        let result: Result<(), TransportError> = (|| {
            let (_, sw) =
                self.transmit_full(&piv::select_by_aid(&fingerprint::HID_CRESCENDO_ACA_AID))?;
            ok_or_apdu("piv aca select", sw)?;

            match current {
                CurrentMgmtAuth::Pin(pin) => self.verify_pin_hid_crescendo_aca(pin)?,
                CurrentMgmtAuth::Key(current_key) => self.aca_xauth_unlock(current_key)?,
            }

            let apdu = Zeroizing::new(match op {
                HidCrescendoXauthKeyOp::Set(alg, key) => {
                    fingerprint::hid_crescendo_aca_put_xauth_key(alg, key)
                        .ok_or(TransportError::PivBadKeyLength)?
                }
                HidCrescendoXauthKeyOp::Delete => {
                    fingerprint::hid_crescendo_aca_put_xauth_key_remove()
                }
            });
            let (_, sw) = self.transmit_full(&apdu)?;
            ok_or_write("piv aca put xauth key", sw)
        })();

        // Step 4: always switch back to PIV — see this method's doc.
        let _ = self.select();
        result
    }

    /// HID Crescendo's device-wide reset — the mechanism behind
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`]: SELECT the ACA
    /// instance, authenticate with `current` (PIN or XAUTH key — the same
    /// choice [`Self::hid_crescendo_aca_put_xauth_key_op`] takes, run fresh
    /// here for the same reason that method's doc gives), send RESET CARD
    /// ([`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_RESET_CARD`]), then
    /// restore XAUTH key 1 to HID's documented factory-delivery value —
    /// read via [`keyroost_piv::compat::default_9b_management_key`] off this
    /// fingerprint's [`keyroost_piv::compat::PivQuirk::Default9bManagementKey`]
    /// row (seeded with
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY`],
    /// the single source of truth for the value) rather than the constant
    /// hard-coded a second time — RESET CARD clears the key outright, but
    /// the as-delivered state ships with it already set to this all-zero
    /// key, and restoring it is also what keeps the device recoverable by
    /// XAUTH alone if a later mistake ever blocks the ACA's own PIN. See
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_RESET_CARD`]'s doc for
    /// exactly what gets wiped (PIV's PKI keys and data containers always;
    /// OATH and, on C4000 only as documented, FIDO — family-dependent).
    ///
    /// **Confirmed on hardware:** the ACA's authenticated security status
    /// does *not* survive RESET CARD, so the PUT XAUTH KEY restore step
    /// right after it re-authenticates first — against
    /// [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_AFTER_RESET`], the
    /// PIN RESET CARD itself just rewrote the card to, not against `current`
    /// (which no longer verifies once the reset has run). If that
    /// re-authentication or the restore itself fails, RESET CARD still
    /// succeeded (the device is fully reset), which reports as
    /// [`FactoryResetOutcome::WipedKeyRestoreFailed`] rather than a hard
    /// error — a caller must not read that as "nothing happened."
    ///
    /// Only the restore step's failure is soft. Every earlier failure — the
    /// SELECT, the authentication, or RESET CARD itself (`SW = 69 82`,
    /// mapped by [`ok_or_write`] to [`TransportError::PivSecurityNotSatisfied`],
    /// same status word and same mapping [`Self::hid_crescendo_aca_put_xauth_key_op`]
    /// relies on) — means the device was never touched, and propagates as a
    /// normal `Err`.
    ///
    /// Always re-SELECTs PIV afterward, whatever the outcome — same
    /// discipline as [`Self::hid_crescendo_aca_put_xauth_key_op`] and every
    /// other temporary-SELECT probe in this file.
    ///
    /// Private: [`Self::factory_reset`] is the one public entry point for
    /// every `PivExtension::Reset`/`ResetGlobal` mechanism this crate
    /// implements — it decides on its own, from the live fingerprint,
    /// whether this method is even the right one to reach for, and wraps
    /// whatever `Err` it returns in [`TransportError::PivResetGlobalFailed`]
    /// so a caller can tell a device-wide-mechanism failure apart from a
    /// burn-dance one. A caller that wants this specific mechanism without
    /// that fingerprint check has no way to ask for it directly any more —
    /// by design, since bypassing the check is exactly what let a caller
    /// attempt HID's ACA RESET CARD against a device that was never
    /// confirmed to have one.
    fn hid_crescendo_aca_reset_card(
        &mut self,
        current: CurrentMgmtAuth<'_>,
    ) -> Result<FactoryResetOutcome, TransportError> {
        use keyroost_piv::fingerprint;

        // Resolved up front, before the ACA gets SELECTed below: this reads
        // `Self::quirks`, which (via `Self::identity`) may itself need to
        // talk to the card the first time it's called in a session, and that
        // has to happen against the currently selected PIV applet, not mid
        // ACA sequence. `PivQuirk::Default9bManagementKey` on this
        // fingerprint's row is always seeded with
        // `fingerprint::HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY` — see that
        // quirk's doc — so the fallback below is purely defensive, never
        // actually reached for a fingerprint that got this far at all.
        let restore_key = keyroost_piv::compat::default_9b_management_key(&self.quirks())
            .unwrap_or(&fingerprint::HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY);

        let result: Result<FactoryResetOutcome, TransportError> = (|| {
            let (_, sw) =
                self.transmit_full(&piv::select_by_aid(&fingerprint::HID_CRESCENDO_ACA_AID))?;
            ok_or_apdu("piv aca select", sw)?;

            match current {
                CurrentMgmtAuth::Pin(pin) => self.verify_pin_hid_crescendo_aca(pin)?,
                CurrentMgmtAuth::Key(current_key) => self.aca_xauth_unlock(current_key)?,
            }

            let (_, sw) = self.transmit_full(&fingerprint::HID_CRESCENDO_ACA_RESET_CARD)?;
            ok_or_write("piv aca reset card", sw)?;

            // Wiped. Everything from here on is the factory-XAUTH-key
            // courtesy restore, not the reset itself — its failure must not
            // read as if RESET CARD had failed.
            //
            // RESET CARD drops the ACA's authenticated security status
            // (confirmed on hardware — see this method's doc) and rewrites
            // its PIN to HID's documented reset-default, so PUT XAUTH KEY
            // below needs a fresh authenticated session against that
            // default, not against `current`. A failure here is folded into
            // the same soft `WipedKeyRestoreFailed` as the restore itself:
            // the device is wiped either way.
            if let Err(e) =
                self.verify_pin_hid_crescendo_aca(fingerprint::HID_CRESCENDO_ACA_PIN_AFTER_RESET)
            {
                trace::line(self.debug, || {
                    format!(
                        "piv aca reauth after reset card (restore factory default): \
                         failed ({e})"
                    )
                });
                return Ok(FactoryResetOutcome::WipedKeyRestoreFailed);
            }

            // `hid_crescendo_aca_put_xauth_key` returning `None` can't
            // actually happen (`restore_key` is 24 bytes, matching
            // `MgmtAlg::TripleDes` exactly), but it's treated as a restore
            // failure rather than unwrapped, so an internal slip here can
            // never panic a destructive device operation.
            let outcome = match fingerprint::hid_crescendo_aca_put_xauth_key(
                keyroost_piv::MgmtAlg::TripleDes,
                restore_key,
            ) {
                Some(apdu) => match self.transmit_full(&apdu) {
                    Ok((_, sw)) if sw == piv::SW_OK => FactoryResetOutcome::WipedGlobal,
                    Ok((_, sw)) => {
                        trace::line(self.debug, || {
                            format!(
                                "piv aca put xauth key (restore factory default): \
                                 rejected (SW {sw:04X})"
                            )
                        });
                        FactoryResetOutcome::WipedKeyRestoreFailed
                    }
                    Err(_) => FactoryResetOutcome::WipedKeyRestoreFailed,
                },
                None => FactoryResetOutcome::WipedKeyRestoreFailed,
            };
            Ok(outcome)
        })();

        // Always switch back to PIV — see this method's doc.
        let _ = self.select();
        result
    }

    /// Generate a fresh asymmetric key pair in `slot`, returning its public key.
    /// Requires prior management-key auth. Overwrites any existing key in the
    /// slot. May require a touch if the slot's touch policy demands it.
    ///
    /// On success, also caches `(alg, public key)` for `slot` in this
    /// session's in-memory key cache, since [`Self::slot_key`] and
    /// [`Self::slot_key_algorithm`]'s only other source for a key this fresh
    /// (the slot's certificate) doesn't exist yet on cards that don't answer
    /// GET METADATA. That only covers later calls *within this same
    /// session* — a caller that needs the key material to outlive this
    /// session (a separate `keyroostctl` invocation, or the GUI's
    /// fresh-session-per-action pattern) has to carry it forward itself and
    /// hand it to a later session via [`Self::remember_pubkey`]; see that
    /// method's doc comment for why this deliberately doesn't do that on its
    /// own.
    pub fn generate_key(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<PublicKey, TransportError> {
        let (data, sw) =
            self.transmit_full(&piv::generate_key(slot, alg, pin_policy, touch_policy))?;
        ok_or_write("piv generate key", sw)?;
        let key = piv::parse_public_key(&data).map_err(TransportError::PivParse)?;
        self.pubkey_cache.remember(slot.key_ref(), alg, key.clone());
        Ok(key)
    }

    /// Seed this session's in-memory key cache for `slot` with `(alg, key)`
    /// directly, without a card round-trip — the same cache
    /// [`Self::generate_key`] populates, and the same one [`Self::slot_key`] /
    /// [`Self::slot_key_algorithm`] fall back to when GET METADATA doesn't
    /// cover the slot.
    ///
    /// This is the deliberately-explicit replacement for what used to be an
    /// automatic on-disk cache: `PivSession` itself keeps no persistence
    /// (no file, nothing cross-process) — a fresh `open()` always starts
    /// empty, by design, so key material a caller isn't actively using never
    /// sits on disk. A caller that needs a metadata-less card's freshly
    /// generated key to survive past this session (a later `keyroostctl`
    /// invocation, or the GUI reopening a session for a later action) has to
    /// hold onto `(alg, key)` itself — in its own process-lifetime state, or
    /// wherever the user chose to put it — and call this before the call that
    /// needs it (`generate_csr`, `self_signed_certificate`, or checking
    /// `slot_key_algorithm` for display). Not verified against the card in
    /// any way: what's remembered here is exactly what's trusted later, so a
    /// caller handing over the wrong slot's key gets a CSR/self-signed
    /// certificate whose SPKI doesn't match the private key that actually
    /// signed it.
    pub fn remember_pubkey(&mut self, slot: Slot, alg: KeyAlg, key: PublicKey) {
        self.pubkey_cache.remember(slot.key_ref(), alg, key);
    }

    /// Import a DER-encoded X.509 certificate into `slot`. Requires prior
    /// management-key auth.
    ///
    /// Tries a single extended-length PUT DATA first; a cert big enough to
    /// need one (any real X.509 cert typically is) that gets rejected falls
    /// back to ISO 7816-4 command chaining — see [`Self::sign`] for why. The
    /// fallback also runs when the extended APDU fails at the PC/SC layer
    /// before any status word comes back (seen with certificates of a few
    /// KB). A card that refuses the certificate's length or has no room for
    /// it yields [`TransportError::PivCertTooLarge`] /
    /// [`TransportError::PivCardFull`].
    pub fn import_certificate(&mut self, slot: Slot, der: &[u8]) -> Result<(), TransportError> {
        let value = piv::encode_certificate(der);
        let tag = slot.cert_object_tag();
        let apdu = piv::put_data(&tag, &value);
        let sw = if self.chain_upfront() {
            trace::line(self.debug, || {
                format!(
                    "! piv import certificate: command chaining up front ({})",
                    self.chain_reason()
                )
            });
            chained_cert_sw(self.transmit_chain(
                "piv import certificate",
                &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
            ))?
        } else {
            let extended = uses_extended_length(&apdu);
            let direct = self.transmit_full(&apdu);
            if retry_chained_after(&direct, extended) {
                if let Err(e) = &direct {
                    trace::line(self.debug, || {
                        format!(
                            "! piv import certificate: extended length failed at the PC/SC \
                             layer ({e}); retrying with command chaining"
                        )
                    });
                }
                chained_cert_sw(self.transmit_chain(
                    "piv import certificate",
                    &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
                ))?
            } else {
                let (_, sw) = direct?;
                if sw == piv::SW_OK || !extended {
                    sw
                } else {
                    trace::line(self.debug, || {
                        format!(
                            "! piv import certificate: extended length rejected (SW={sw:04X}); \
                             retrying with command chaining"
                        )
                    });
                    chained_cert_sw(self.transmit_chain(
                        "piv import certificate",
                        &piv::put_data_chained(&tag, &value, CHAIN_CHUNK),
                    ))?
                }
            }
        };
        cert_write_result(slot, der.len(), sw)
    }

    /// Write a CHUID (Card Holder Unique Identifier) to the card: `guid` is
    /// the 16-byte GUID (tag `0x34`) — see [`random_chuid_guid`] for a
    /// host-side-only, no-card-I/O way to generate one a caller can pre-fill
    /// an input with and let the user overwrite — and `expiration` is the
    /// `YYYYMMDD` expiration date (tag `0x35`; see
    /// [`keyroost_piv::chuid_expiration_in_days`]). Requires prior
    /// management-key auth ([`authenticate_management`]).
    ///
    /// Mirrors `yubico-piv-tool`'s `set-chuid` (see [`keyroost_piv::encode_chuid`]
    /// for the byte-for-byte template match): Windows' PIV minidriver caches
    /// a card's contents by its CHUID, so after writing a new certificate or
    /// key it may keep showing stale data until the CHUID changes — this is
    /// the standard fix, not a workaround specific to any one vendor's card.
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    pub fn new_chuid(
        &mut self,
        guid: &[u8; 16],
        expiration: &[u8; 8],
    ) -> Result<(), TransportError> {
        let value = piv::encode_chuid(guid, expiration);
        let (_, sw) = self.transmit_full(&piv::put_data(&piv::OBJECT_CHUID, &value))?;
        ok_or_write("piv new chuid", sw)
    }

    /// Read the card's CHUID: FASC-N, GUID, and expiration date (the
    /// signature and LRC fields are parsed away — see
    /// [`keyroost_piv::parse_chuid`]). `None` when the object is empty/absent
    /// or doesn't parse as a CHUID. No PIN required — CHUID is a public data
    /// object, like a certificate.
    pub fn read_chuid(&mut self) -> Result<Option<keyroost_piv::Chuid>, TransportError> {
        let (data, sw) = self.transmit_full(&piv::get_data(&piv::OBJECT_CHUID))?;
        if sw != piv::SW_OK {
            return Ok(None);
        }
        let inner = piv::unwrap_data_object(&data).map_err(TransportError::PivParse)?;
        Ok(piv::parse_chuid(inner))
    }

    /// Clear `slot`'s certificate object (standard PIV; universal across
    /// firmware). Removes only the X.509 certificate; the slot's private key
    /// persists. Requires prior management-key auth ([`authenticate_management`]).
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    pub fn clear_certificate(&mut self, slot: Slot) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::clear_certificate(slot))?;
        ok_or_write("piv clear certificate", sw)
    }

    /// Delete `slot`'s private key (Yubico MOVE-to-`0xFF` extension). Permanently
    /// erases the key material; the certificate object is untouched. This is a
    /// Yubico vendor extension (YubiKey firmware 5.7+); it is **not**
    /// version-gated here — a card that doesn't implement it refuses the APDU,
    /// and [`Self::feature_gate`] is the way to check ahead of that. Requires
    /// prior management-key auth ([`authenticate_management`]).
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    pub fn delete_key(&mut self, slot: Slot) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::delete_key(slot))?;
        ok_or_write("piv delete key", sw)?;
        self.pubkey_cache.evict(slot.key_ref());
        Ok(())
    }

    /// Read the DER-encoded certificate stored in `slot`, or `None` when the
    /// slot has none — `6A82` (no object), an empty `53 00` template, or a
    /// body that isn't a `0x53` data object at all. A read-only public
    /// object: no PIN, and a malformed body is reported as absent rather than
    /// erroring the call (a real card doesn't produce one; `slot_status` and
    /// `status_detailed` derive occupancy straight from this).
    pub fn read_certificate(&mut self, slot: Slot) -> Result<Option<Vec<u8>>, TransportError> {
        self.cert_object(slot)?
            .map_err(|reason| TransportError::PivCertUnreadable { slot, reason })
    }

    /// One GET DATA of `slot`'s certificate object, decoded: the outer
    /// `Result` is the card exchange, the inner one whether a certificate
    /// that is there can be read. Status views use this directly so one
    /// unreadable slot is reported, not fatal to the whole snapshot.
    fn cert_object(
        &mut self,
        slot: Slot,
    ) -> Result<Result<Option<Vec<u8>>, CertUnreadable>, TransportError> {
        let (data, sw) = self.transmit_full(&piv::get_data(&slot.cert_object_tag()))?;
        if sw != piv::SW_OK {
            return Ok(Ok(None));
        }
        Ok(cert_object_der(&data))
    }

    /// Yubico ATTEST: the self-signed attestation certificate for `slot`'s key
    /// (DER), proving it was generated on-card. Firmware 4.3+ (older firmware,
    /// and non-Yubico PIV cards, refuse this instruction). No PIN required.
    ///
    /// Checks [`keyroost_piv::compat::PivExtension::Attest`] before sending
    /// anything, same reasoning as [`Self::metadata`]'s
    /// [`GetMetadata`](keyroost_piv::compat::PivExtension::GetMetadata)
    /// check — so a caller doesn't pay for a guaranteed-refused round trip
    /// (and [`Self::resolve_policy`]'s ATTEST fallback, which every one of
    /// this fingerprint's slots hits since GET METADATA never names a
    /// policy either, doesn't send four of them per status read). The
    /// synthetic `SW = 6D 00` this returns without any card I/O matches
    /// exactly what a real unsupported-instruction refusal looks like, so
    /// every caller of `attest` sees the same error shape either way.
    pub fn attest(&mut self, slot: Slot) -> Result<Vec<u8>, TransportError> {
        if self.extension_gate(keyroost_piv::compat::PivExtension::Attest)
            == keyroost_piv::compat::FeatureGate::Unsupported
        {
            // `6D 00` (instruction not supported) is exactly what this
            // fingerprint's real refusal looks like — see `Self::attest`'s
            // doc for why this is worth faking rather than sending anything.
            return Err(TransportError::Apdu {
                label: "piv attest",
                sw1: 0x6D,
                sw2: 0x00,
            });
        }
        let (data, sw) = self.transmit_full(&piv::attest(slot.key_ref()))?;
        ok_or_write("piv attest", sw)?;
        Ok(data)
    }

    /// Read `slot`'s PIN/touch policy for display:
    ///
    /// 1. GET METADATA, tried unconditionally — cards that don't support it
    ///    (pre-5.3 firmware, or non-Yubico PIV) simply answer with something
    ///    other than `9000`/no policy, which falls through to step 2.
    /// 2. The ATTEST certificate's Yubico key-policy extension
    ///    (`1.3.6.1.4.1.41482.3.8`) — GET METADATA predates policy reporting,
    ///    but ATTEST itself has existed since 4.3. ATTEST is itself a Yubico
    ///    vendor instruction, so a non-Yubico PIV card refuses it too; that
    ///    refusal is handled the same as everything else here, not specially.
    ///
    /// `None` throughout means "not available for display", not a wire
    /// error — this is an informational read, not a precondition for a write,
    /// so every failure mode (missing extension, unparsable metadata, ATTEST
    /// itself being unsupported) collapses to the same answer.
    pub fn slot_policy(&mut self, slot: Slot) -> Option<(PinPolicy, TouchPolicy)> {
        let meta = self.metadata(slot.key_ref());
        self.resolve_policy(slot, meta.as_ref())
    }

    /// [`Self::slot_policy`]'s two-step resolution from a GET METADATA reply
    /// the caller already has: its `policy` bytes, else the ATTEST
    /// certificate's key-policy extension. Split out so [`Self::status_detailed`]
    /// shares the exact same order without a second GET METADATA.
    fn resolve_policy(
        &mut self,
        slot: Slot,
        meta: Option<&Metadata>,
    ) -> Option<(PinPolicy, TouchPolicy)> {
        let (pin, touch) = if let Some(policy) = meta.and_then(|m| m.policy) {
            policy
        } else {
            // Non-Yubico PIV cards refuse this vendor instruction outright
            // (a status word, not `9000`) — `.ok()?` turns that refusal
            // into the same "no policy available" `None` as every other
            // failure mode here.
            let cert = self.attest(slot).ok()?;
            keyroost_piv::x509_parse::parse_key_policy_extension(&cert)
                .ok()
                .flatten()?
        };
        Some((PinPolicy::from_id(pin)?, TouchPolicy::from_id(touch)?))
    }

    /// Read `slot`'s key algorithm for display, compatible with any PIV
    /// token — not just a YubiKey new enough for GET METADATA (5.3+):
    ///
    /// 1. GET METADATA. When it names an algorithm, that's authoritative —
    ///    return it.
    /// 2. This session's in-memory key cache (populated by
    ///    [`Self::generate_key`], or seeded explicitly via
    ///    [`Self::remember_pubkey`]). This is what makes a freshly generated key
    ///    show up immediately on metadata-less firmware: there's no
    ///    certificate yet for step 3 to read (self-sign/import hasn't run),
    ///    and GET METADATA's silence on such firmware doesn't mean "empty" —
    ///    it means "doesn't exist", so without this step a slot that was
    ///    *just* populated would still display as empty. A caller reading
    ///    status in a fresh session has to `remember_pubkey` first if it wants
    ///    this step to see anything.
    /// 3. Otherwise, fall back to the slot's certificate (a standard PIV data
    ///    object every card serves) and parse the algorithm out of its
    ///    SubjectPublicKeyInfo directly.
    ///
    /// Unlike [`Self::slot_key`] — which this does *not* replace — this never
    /// needs the actual public key bytes, only the algorithm, so the
    /// certificate fallback is enough; `slot_key`'s callers (CSR/self-sign)
    /// need the raw key material GET METADATA carries and stay
    /// metadata-only.
    pub fn slot_key_algorithm(&mut self, slot: Slot) -> Option<KeyAlg> {
        let meta = self.metadata(slot.key_ref());
        // Steps 1–2 need no card read beyond the GET METADATA just done.
        if let Some(alg) = self.algorithm_without_cert(slot, meta.as_ref()) {
            return Some(alg);
        }
        // HID Crescendo C2300's live substitute for GET METADATA, which this
        // fingerprint never answers — see
        // `Self::hid_crescendo_slot_algorithm`'s doc. A no-op (`None`)
        // on every other fingerprint.
        if let Some(alg) = self.hid_crescendo_slot_algorithm(slot) {
            return Some(alg);
        }
        // Step 3: the slot certificate's SubjectPublicKeyInfo.
        self.read_certificate(slot)
            .ok()
            .flatten()
            .and_then(|der| piv::x509_parse::parse_key_algorithm(&der).ok().flatten())
    }

    /// The first two of [`Self::slot_key_algorithm`]'s three steps — GET
    /// METADATA's `algorithm` (from a reply the caller already has), then
    /// this session's generated-key cache — i.e. everything that needs no
    /// certificate read. [`Self::status_detailed`] appends the same step-3
    /// certificate fallback with a cert it already holds.
    fn algorithm_without_cert(&self, slot: Slot, meta: Option<&Metadata>) -> Option<KeyAlg> {
        meta.and_then(|m| m.algorithm)
            .and_then(KeyAlg::from_id)
            .or_else(|| self.pubkey_cache.get(slot.key_ref()).map(|(alg, _)| *alg))
    }

    /// Ask `slot`'s private key to sign a *prepared* block via GENERAL
    /// AUTHENTICATE: a full PKCS#1 v1.5 padded block for RSA, the raw hash for
    /// ECDSA, or the raw message for Ed25519 (see
    /// [`keyroost_piv::x509::signature_hash`]). Requires a verified PIN —
    /// immediately prior for the signature slot (9C), whose policy is
    /// PIN-per-use. ECDSA signatures come back DER-encoded (`SEQUENCE{r,s}`),
    /// RSA/Ed25519 as raw blocks — either drops verbatim into an X.509
    /// signature BIT STRING.
    ///
    /// Tries a single extended-length GENERAL AUTHENTICATE first; for a key
    /// large enough to need one (RSA-2048+, or Ed25519 with a long enough
    /// TBS) that gets rejected falls back to ISO 7816-4 command chaining —
    /// confirmed necessary on a Token2 PIV token's contact interface, which
    /// answers a well-formed extended-`Lc` GENERAL AUTHENTICATE/PUT DATA with
    /// `SW=6A80` (unlike the `6700`/`6883` YubiKey's OpenPGP applet uses for
    /// the same condition — see
    /// [`OpenPgpSession::import_key`](crate::OpenPgpSession::import_key)) but
    /// accepts the identical data chained. The fallback only fires when the
    /// first attempt actually used extended-length encoding, so a genuine
    /// error on a short-form command (bad PIN state, wrong key, …) isn't
    /// retried.
    pub fn sign(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        prepared: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let key_ref = slot.key_ref();
        self.general_auth_dyn_auth(
            "piv sign",
            &piv::general_auth_sign(alg, key_ref, prepared),
            &piv::general_auth_sign_chained(alg, key_ref, prepared, CHAIN_CHUNK),
        )
    }

    /// Ask `slot`'s RSA private key to raw-decrypt `ciphertext` (a `k`-byte
    /// PKCS#1 block) via GENERAL AUTHENTICATE. Wire-identical to [`Self::sign`]
    /// — the card does the same raw RSA private-key operation for both, and
    /// the input rides the same dynamic-auth `0x81` field — but named
    /// separately so a decrypt call site reads as one. Needs a verified PIN
    /// immediately prior, same as `sign`.
    pub fn decrypt(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let key_ref = slot.key_ref();
        self.general_auth_dyn_auth(
            "piv decrypt",
            &piv::general_auth_sign(alg, key_ref, ciphertext),
            &piv::general_auth_sign_chained(alg, key_ref, ciphertext, CHAIN_CHUNK),
        )
    }

    /// Run ECDH on `slot`'s private key against `peer_public_key` via GENERAL
    /// AUTHENTICATE key-establishment (dynamic-auth tag `0x85`).
    /// `peer_public_key` is `04 || X || Y` for P-256/P-384 or the raw 32-byte
    /// point for X25519; the reply is the raw shared secret `Z` (the
    /// x-coordinate for the NIST curves). Needs a verified PIN immediately
    /// prior, same as [`Self::sign`].
    pub fn key_agree(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let key_ref = slot.key_ref();
        self.general_auth_dyn_auth(
            "piv key-agree",
            &piv::general_auth_key_agree(alg, key_ref, peer_public_key),
            &piv::general_auth_key_agree_chained(alg, key_ref, peer_public_key, CHAIN_CHUNK),
        )
    }

    /// The GENERAL AUTHENTICATE transmit shared by [`Self::sign`],
    /// [`Self::decrypt`], and [`Self::key_agree`]: send `single` once, and if
    /// it used extended-length encoding and the card rejected it (`SW != 9000`),
    /// retry with the `chained` APDU sequence. Returns the response's `0x82`
    /// dynamic-auth value. The fallback only fires when the first attempt
    /// actually used extended-length encoding, so a genuine error on a
    /// short-form command (bad PIN state, wrong key, …) isn't retried.
    fn general_auth_dyn_auth(
        &mut self,
        label: &'static str,
        single: &[u8],
        chained: &[Vec<u8>],
    ) -> Result<Vec<u8>, TransportError> {
        let (data, sw) = if self.chain_upfront() {
            trace::line(self.debug, || {
                format!(
                    "! {label}: command chaining up front ({})",
                    self.chain_reason()
                )
            });
            self.transmit_chain(label, chained)?
        } else {
            let (data, sw) = self.transmit_full(single)?;
            if sw == piv::SW_OK || !uses_extended_length(single) {
                (data, sw)
            } else {
                trace::line(self.debug, || {
                    format!(
                        "! {label}: extended length rejected (SW={sw:04X}); retrying with \
                         command chaining"
                    )
                });
                self.transmit_chain(label, chained)?
            }
        };
        ok_or_write(label, sw)?;
        piv::parse_general_auth(&data, 0x82)
            .map(<[u8]>::to_vec)
            .map_err(TransportError::PivParse)
    }

    /// The algorithm and public key of the key stored in `slot`: from GET
    /// METADATA (firmware 5.3+) when the card actually names both, else from
    /// this session's in-memory key cache. That cache is populated only by a
    /// prior [`Self::generate_key`] on `slot` in *this* session, or by a caller
    /// explicitly carrying the key material forward via [`Self::remember_pubkey`]
    /// — that's what lets CSR/self-sign work right after generation on cards
    /// that don't support GET METADATA (older YubiKeys, non-Yubico PIV
    /// tokens): the card refuses to name the key material any other way, so
    /// the cache is the only source left once GENERATE ASYMMETRIC has already
    /// told us what it made, and this crate keeps no on-disk or
    /// cross-process copy of that on its own (see [`Self::remember_pubkey`]).
    ///
    /// GET METADATA answering `SW_OK` is not by itself treated as authoritative
    /// — some implementations (Nitrokey's `piv-authenticator`) accept the
    /// instruction but reply with an empty body for slots they haven't wired
    /// reporting up for yet, rather than failing it outright. That's
    /// functionally identical to "no GET METADATA support" for our purposes,
    /// so `metadata_key_material` is the single gate for "does this reply
    /// actually name the key", and only a `Some` from it short-circuits the
    /// cache fallback below.
    ///
    /// Called by [`Self::generate_csr`]/[`Self::self_signed_certificate`]
    /// *before* they verify the PIN — GET METADATA is an unauthenticated
    /// read (confirmed against real hardware: it succeeds before any PIN
    /// VERIFY in the same session), so resolving the key first and verifying
    /// right before the signing GENERAL AUTHENTICATE keeps that VERIFY the
    /// last command before the signature on every card, rather than risking
    /// a metadata probe sitting in between — some cards (Nitrokey's
    /// `piv-authenticator` observed so far) don't tolerate any intervening
    /// APDU between a PIN verify and the signing operation it authorizes.
    ///
    /// Errors when the slot is empty, GET METADATA doesn't name this slot's
    /// key *and* nothing was generated into `slot` in this session (nor
    /// handed to it via `remember_pubkey`), or a cached entry was invalidated
    /// by a later delete/move/reset.
    pub fn slot_key(&mut self, slot: Slot) -> Result<(KeyAlg, PublicKey), TransportError> {
        let key_ref = slot.key_ref();
        if let Some(md) = self.metadata(key_ref) {
            if let Some((alg, raw)) = metadata_key_material(&md) {
                let key = public_key_from_metadata(raw).map_err(TransportError::PivParse)?;
                return Ok((alg, key));
            }
        }
        if let Some(cached) = self.pubkey_cache.get(key_ref).cloned() {
            return Ok(cached);
        }
        Err(TransportError::MalformedResponse(
            "slot has no key, or GET METADATA doesn't name this slot's key and \
             the key material wasn't handed to this session — run `piv generate-key` \
             on this slot in this same session, or pass its previously saved \
             key material to this command, so it can be cached for \
             CSR/self-sign",
        ))
    }

    /// Build a PKCS#10 certificate-signing request for the key in `slot`,
    /// signed on the card, returned as PEM. The slot must hold a key
    /// (generated or imported). Verifies `pin` itself, deliberately placed
    /// *after* resolving the slot's key material ([`Self::slot_key`]) and
    /// *immediately* before the signing [`Self::sign`] call — see
    /// `slot_key`'s doc comment for why that ordering matters.
    pub fn generate_csr(
        &mut self,
        slot: Slot,
        subject: &str,
        pin: &[u8],
    ) -> Result<String, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let subject = piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = piv::spki::subject_public_key_info(&key, alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        let cri = piv::x509::csr_info(&subject, &spki);
        let prepared = prepared_block(alg, &cri)?;
        self.verify_pin(pin)?;
        let sig = self.sign(slot, alg, &prepared)?;
        let der = piv::x509::assemble(&cri, alg, &sig).map_err(TransportError::X509)?;
        Ok(piv::x509::pem_csr(&der))
    }

    /// Create a self-signed certificate for the key in `slot` (validity in
    /// unix seconds), sign it on the card, **import it into the slot**, and
    /// return the DER. Requires prior management-key auth (for the import).
    /// Verifies `pin` itself, deliberately placed *after* resolving the
    /// slot's key material ([`Self::slot_key`]) and *immediately* before the
    /// signing [`Self::sign`] call — see `slot_key`'s doc comment for why
    /// that ordering matters.
    pub fn self_signed_certificate(
        &mut self,
        slot: Slot,
        subject: &str,
        not_before: i64,
        not_after: i64,
        pin: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let subject = piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = piv::spki::subject_public_key_info(&key, alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        // 16 random bytes keep the serial unique and well under RFC 5280's
        // 20-octet ceiling even after the positive-INTEGER zero prefix.
        let mut serial = [0u8; 16];
        getrandom::getrandom(&mut serial).map_err(|_| TransportError::HostRngFailed)?;
        let tbs = piv::x509::tbs_certificate(&serial, alg, &subject, not_before, not_after, &spki)
            .map_err(TransportError::X509)?;
        let prepared = prepared_block(alg, &tbs)?;
        self.verify_pin(pin)?;
        let sig = self.sign(slot, alg, &prepared)?;
        let der = piv::x509::assemble(&tbs, alg, &sig).map_err(TransportError::X509)?;
        self.import_certificate(slot, &der)?;
        Ok(der)
    }

    /// Relocate a slot's private key to another slot (Yubico MOVE KEY). Refuses
    /// a same-slot move and an occupied destination (GET METADATA pre-check —
    /// the card also refuses, this gives a clear error first). Moves ONLY the
    /// key; the source slot's certificate stays put. Requires prior
    /// management-key auth ([`authenticate_management`]), same as
    /// [`delete_key`].
    ///
    /// This is a Yubico vendor extension (YubiKey firmware 5.7+) and is
    /// **not** version-gated here — an older card refuses the APDU itself.
    /// Use [`Self::feature_gate`] to check ahead of that.
    ///
    /// [`authenticate_management`]: PivSession::authenticate_management
    /// [`delete_key`]: PivSession::delete_key
    pub fn move_key(&mut self, src: Slot, dest: Slot) -> Result<(), TransportError> {
        if src.key_ref() == dest.key_ref() {
            return Err(TransportError::MalformedResponse(
                "source and destination slots are the same",
            ));
        }
        if self.slot_has_key(dest)? {
            return Err(TransportError::PivDestinationOccupied(dest));
        }
        let (_, sw) = self.transmit_full(&piv::move_key(src, dest))?;
        ok_or_write("piv move key", sw)?;
        // The key itself relocated, not just its reference — carry a cached
        // entry along with it rather than dropping it, so a subsequent
        // CSR/self-sign at `dest` still works on metadata-less firmware.
        self.pubkey_cache.migrate(src.key_ref(), dest.key_ref());
        Ok(())
    }

    /// Whether `slot` holds a private key, via GET METADATA. Works for retired
    /// slots too — it just reads whatever key reference `slot` maps to. This is
    /// the on-demand occupancy check (not part of [`status`]'s snapshot, which
    /// stays 4 GET DATA calls rather than 24 by never touching retired slots).
    ///
    /// Derives occupancy from [`metadata`], which folds a transient/comms
    /// error into the same `None` as a genuinely empty slot, so a rare
    /// transient failure here is reported as an empty slot; the card's own
    /// refusal to write over an occupied destination is the backstop.
    ///
    /// A `Some` from [`metadata`] is *not* by itself "occupied": some
    /// implementations (Nitrokey's `piv-authenticator`, and PivApplet as seen
    /// on a Token2 fingerprint trace) answer `SW_OK` for every retired key
    /// reference whether or not a key was ever generated there, with an empty
    /// or key-less body for the ones that weren't. That reply is
    /// indistinguishable from "no key" and would otherwise mark every retired
    /// slot present — so this gates on [`metadata_key_material`], the same
    /// "does this reply actually name the key" check [`Self::slot_key`] uses,
    /// rather than on the GET METADATA status word alone.
    ///
    /// [`status`]: PivSession::status
    /// [`metadata`]: PivSession::metadata
    pub fn slot_has_key(&mut self, slot: Slot) -> Result<bool, TransportError> {
        Ok(self
            .metadata(slot.key_ref())
            .is_some_and(|md| metadata_key_material(&md).is_some()))
    }

    /// Reset the PIV application to factory defaults. Always sends the bare
    /// RESET APDU and reports whatever the card says — this method does
    /// nothing to detect or satisfy either precondition below itself:
    ///
    /// * The widespread YubiKey-mimicking convention: succeeds only when
    ///   **both** the PIN and PUK are already blocked (the card enforces
    ///   this); otherwise it returns `6983` or `6985` (a genuine YubiKey's own
    ///   choice, per Yubico's docs), either mapped to
    ///   [`TransportError::PivResetNotAllowed`].
    /// * Some fingerprints instead require an authenticated management-key
    ///   session before RESET is accepted — flagged by
    ///   [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`] — with
    ///   no PIN/PUK blocking involved at all. This method itself still does
    ///   nothing to satisfy that: it never authenticates, so called directly
    ///   on a quirked device with no prior authenticated session in force,
    ///   this call is expected to fail (however the card reports "management
    ///   auth needed" — unverified, since no such session gets attempted
    ///   here). [`Self::factory_reset`] is what actually authenticates first
    ///   on such a device (`Self::authenticate_management_current`) before
    ///   reaching this same method.
    ///
    /// A caller that wants to know which convention a device follows ahead
    /// of time should check `self.quirks()` for the quirk above, or go
    /// through [`Self::plan_factory_reset`]/[`Self::factory_reset`], which
    /// already do and route around this method's PIN/PUK-blocking assumption
    /// accordingly.
    pub fn reset(&mut self) -> Result<(), TransportError> {
        let (_, sw) = self.transmit_full(&piv::reset())?;
        // A YubiKey answers RESET's "PIN and PUK must already be blocked"
        // precondition with 6985 (conditions of use not satisfied), not 6983
        // per Yubico's own docs — see SW_CONDITIONS_NOT_SATISFIED. Other
        // fingerprints have been observed using 6983 for the identical
        // precondition, so both map to the same outcome here.
        if sw == piv::SW_AUTH_BLOCKED || sw == piv::SW_CONDITIONS_NOT_SATISFIED {
            return Err(TransportError::PivResetNotAllowed);
        }
        ok_or_write("piv reset", sw)?;
        // Wipes every slot; nothing cached survives it. `factory_reset` reaches
        // this same reset() at the end of its own path, so it's covered too.
        self.pubkey_cache.clear();
        Ok(())
    }

    /// The raw [`keyroost_piv::compat::PivExtension::ResetGlobal`] gate for
    /// this session's applet — exposed on its own because nothing else here
    /// already surfaces it standalone: [`Self::plan_factory_reset`] resolves
    /// only [`PivExtension::Reset`], and [`Self::global_reset_available`]
    /// folds this gate together with `Reset`'s (via OR) and the
    /// [`PivQuirk::ResetNeedsManagementAuth`] quirk (via AND) into one
    /// `bool`, losing this gate's own value along the way. A caller that
    /// needs to tell "`Reset` is `Unsupported` AND `ResetGlobal` is also
    /// `Unsupported`" apart from "`Reset` is `Unsupported` but `ResetGlobal`
    /// might still offer something" needs this method alongside
    /// `plan_factory_reset`'s [`FactoryResetPlan::Unsupported`] (which alone
    /// only proves the first half).
    ///
    /// Read-only, same cost as [`Self::plan_factory_reset`]: no APDU beyond
    /// [`Self::identity`]'s fingerprint probe, cached after the first call
    /// this session.
    #[must_use]
    pub fn reset_global_gate(&mut self) -> keyroost_piv::compat::FeatureGate {
        self.extension_gate(keyroost_piv::compat::PivExtension::ResetGlobal)
    }

    /// The raw [`keyroost_piv::compat::PivExtension::PinManagementAuth`] gate
    /// for this session's applet — exposed standalone for a caller that needs
    /// to know whether a PIN is even a candidate credential *before* asking
    /// for one, e.g. `keyroostctl factory-reset`'s (and `keyroostctl piv
    /// reset`'s) abort-early message when [`Self::global_reset_available`]
    /// (respectively [`Self::plan_factory_reset`] resolving
    /// [`FactoryResetPlan::NeedsManagementAuth`]) is true: it names the PIN
    /// option only when this gate says it applies, and flags it as
    /// unverified when that's all this gate can confirm.
    ///
    /// Read-only, same cost as [`Self::reset_global_gate`]: no APDU beyond
    /// [`Self::identity`]'s fingerprint probe, cached after the first call
    /// this session.
    #[must_use]
    pub fn pin_management_auth_gate(&mut self) -> keyroost_piv::compat::FeatureGate {
        self.extension_gate(keyroost_piv::compat::PivExtension::PinManagementAuth)
    }

    /// Resolve [`FactoryResetPlan`] for this session's applet — the PIV-only
    /// shape, from [`keyroost_piv::compat::PivExtension::Reset`] alone.
    /// Read-only: costs no PIN/PUK attempt, and no APDU at all beyond
    /// [`Self::identity`]'s fingerprint probe (itself cached after the first
    /// call this session).
    ///
    /// Most callers want [`Self::preview_factory_reset`] instead, which
    /// additionally checks
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`] first — the same
    /// order [`Self::factory_reset`] itself checks in. This method alone says
    /// nothing about that axis; call it directly only when the PIV-only
    /// shape specifically is what's needed (e.g. a caller that already knows
    /// `ResetGlobal` doesn't apply here).
    #[must_use]
    pub fn plan_factory_reset(&mut self) -> FactoryResetPlan {
        use keyroost_piv::compat::{FeatureGate, PivExtension, PivQuirk};
        match self.extension_gate(PivExtension::Reset) {
            FeatureGate::Unsupported => FactoryResetPlan::Unsupported,
            FeatureGate::Unverified => FactoryResetPlan::Unverified,
            FeatureGate::Supported => {
                if self.quirks().contains(&PivQuirk::ResetNeedsManagementAuth) {
                    FactoryResetPlan::NeedsManagementAuth
                } else {
                    FactoryResetPlan::BurnPinPukThenReset
                }
            }
        }
    }

    /// Resolve [`PivResetPreview`] for this session's applet: what
    /// [`Self::factory_reset`] will attempt *first*, checking
    /// [`keyroost_piv::compat::PivExtension::ResetGlobal`] first (a
    /// device-wide mechanism wins when available) and falling back to
    /// [`Self::plan_factory_reset`]'s PIV-only shape otherwise — the exact
    /// order [`Self::factory_reset`] itself dispatches on. Read-only, same
    /// cost as [`Self::plan_factory_reset`]: no APDU beyond
    /// [`Self::identity`]'s fingerprint probe, cached after the first call
    /// this session.
    ///
    /// "First" because it can't predict [`Self::factory_reset`]'s one
    /// runtime fallback: when this resolves [`PivResetPreview::Global`] off
    /// an *unverified* `ResetGlobal` gate and that attempt then fails,
    /// `factory_reset` tries the PIV-only shape next rather than giving up
    /// (see its doc) — something this method has no way to predict without
    /// actually attempting the device-wide mechanism first. Still the right
    /// preview to show ahead of time: `Global` is what actually runs in the
    /// overwhelmingly common case (the attempt succeeds), and a caller
    /// describing what's about to happen shouldn't hedge across a fallback
    /// that only matters when that attempt fails.
    #[must_use]
    pub fn preview_factory_reset(&mut self) -> PivResetPreview {
        use keyroost_piv::compat::FeatureGate;
        if self.reset_global_gate() != FeatureGate::Unsupported {
            return PivResetPreview::Global;
        }
        match self.plan_factory_reset() {
            FactoryResetPlan::Unsupported => PivResetPreview::Unsupported,
            other => PivResetPreview::Piv(other),
        }
    }

    /// Whether either reset extension — [`PivExtension::Reset`] or
    /// [`PivExtension::ResetGlobal`] — resolves anything other than
    /// [`FeatureGate::Unsupported`] (i.e. `Supported` *or* `Unverified` on
    /// at least one of the two) **and** this fingerprint carries
    /// [`keyroost_piv::compat::PivQuirk::ResetNeedsManagementAuth`]. `false`
    /// otherwise.
    ///
    /// Deliberately not narrowed to `ResetGlobal == Supported`: that would
    /// exclude [`HidCrescendoVariant::Generic`][generic], the one real
    /// fingerprint this matters for today where it actually bites —
    /// `RESET_GLOBAL_VERDICTS` carries no row for `Generic` (see that
    /// table's doc for why: RESET CARD's own documentation names only
    /// C2300/C4000, so there's no basis to *claim* Generic supports it), so
    /// `ResetGlobal` resolves `Unverified` there, not `Supported` — yet the
    /// underlying ACA mechanism is expected to work on Generic too, the same
    /// way [`Self::set_management_key`]/
    /// [`Self::delete_management_key_hid_crescendo`]'s HID Crescendo
    /// fallback already matches on the fingerprint generically (`let
    /// AppletFingerprint::HidCrescendo(variant) = self.fingerprint()`, any
    /// variant) rather than singling out named models. `Reset` is checked
    /// too, alongside `ResetGlobal`, for the same "don't require `Supported`
    /// specifically" reasoning — either extension being anything but a
    /// confirmed dead end is enough to justify collecting a credential the
    /// quirk says is needed; [`Self::hid_crescendo_aca_reset_card`] itself
    /// still decides whether the attempt actually succeeds.
    ///
    /// Read-only, same cost profile as [`Self::plan_factory_reset`]: no APDU
    /// beyond [`Self::identity`]'s fingerprint probe, cached after the first
    /// call this session — resolving both gates plus the quirk costs exactly
    /// one fingerprint, not three.
    ///
    /// [generic]: keyroost_piv::fingerprint::HidCrescendoVariant::Generic
    #[must_use]
    pub fn global_reset_available(&mut self) -> bool {
        use keyroost_piv::compat::{FeatureGate, PivExtension, PivQuirk};
        let reset = self.extension_gate(PivExtension::Reset);
        let reset_global = self.extension_gate(PivExtension::ResetGlobal);
        (reset != FeatureGate::Unsupported || reset_global != FeatureGate::Unsupported)
            && self.quirks().contains(&PivQuirk::ResetNeedsManagementAuth)
    }

    /// The well-known factory-default management-key bytes for this
    /// session's applet, if keyroost has one on record —
    /// [`keyroost_piv::compat::default_9b_management_key`] over
    /// [`Self::quirks`]. `None` means keyroost has no known default for
    /// this fingerprint/version, the same signal
    /// [`Self::global_reset_available`]'s caller uses to disable its "use
    /// the default" convenience. Whichever mechanism
    /// [`Self::factory_reset`] ends up running when
    /// [`Self::global_reset_available`] is true — the device-wide ACA XAUTH
    /// round or the PIV-only management-key round — resolves its credential
    /// from this same quirk (HID Crescendo has no standard PIV management
    /// key at all; see [`keyroost_piv::compat::PivQuirk::Default9bManagementKey`]'s
    /// doc), so one accessor serves both. Read-only, same cost profile as
    /// [`Self::global_reset_available`]: no APDU beyond the identity probe,
    /// cached after the first call this session.
    #[must_use]
    pub fn default_management_key(&mut self) -> Option<&'static [u8]> {
        keyroost_piv::compat::default_9b_management_key(&self.quirks())
    }

    /// Authenticate PIV management via whichever `current` credential a
    /// caller supplied — [`CurrentMgmtAuth::Key`] runs the standard round
    /// with the algorithm inferred from the key's own length (the same
    /// inference [`Self::authenticate_management_via_pin`]'s
    /// PIN-protected-key path already uses),
    /// [`CurrentMgmtAuth::Pin`] runs [`Self::authenticate_management_via_pin`]
    /// itself. Used by [`Self::factory_reset`]'s
    /// [`FactoryResetPlan::NeedsManagementAuth`] path, where — unlike
    /// [`Self::authenticate_management_via_pin`]'s own callers, which already
    /// know PIN-based auth is what a given fingerprint offers — the caller
    /// may be handed either kind of credential without knowing ahead of time
    /// which one this fingerprint actually wants. Public so `keyroostctl
    /// piv reset` can run the exact same round in front of a *plain*
    /// [`Self::reset`] — unlike [`Self::factory_reset`], it must never reach
    /// for the device-wide [`PivExtension::ResetGlobal`] mechanism, so it
    /// authenticates here and sends [`Self::reset`] itself rather than
    /// calling [`Self::factory_reset`].
    pub fn authenticate_management_current(
        &mut self,
        current: CurrentMgmtAuth<'_>,
    ) -> Result<(), TransportError> {
        match current {
            CurrentMgmtAuth::Key(key) => {
                let alg = self.resolve_management_key_algorithm(key.len())?;
                self.authenticate_management(alg, key)
            }
            CurrentMgmtAuth::Pin(pin) => self.authenticate_management_via_pin(pin),
        }
    }

    /// Factory-reset PIV the manufacturer-intended way, whichever mechanism
    /// this fingerprint actually offers — the one method every reset path
    /// this crate implements funnels through, so a caller never has to
    /// decide between them itself:
    ///
    /// 1. [`keyroost_piv::compat::PivExtension::ResetGlobal`] resolves
    ///    anything but `Unsupported` → the device-wide mechanism (HID
    ///    Crescendo's ACA RESET CARD today), which takes PIV down with it
    ///    alongside at least one other applet. Always needs `current` — the
    ///    ACA's own protocol requires an authenticated session regardless of
    ///    any quirk; [`TransportError::PivResetNeedsManagementAuth`] if
    ///    `current` is `None`.
    ///
    ///    If this fails and the gate was only
    ///    [`keyroost_piv::compat::FeatureGate::Unverified`] (never a confirmed
    ///    [`keyroost_piv::compat::FeatureGate::Supported`]) — falls through to
    ///    step 2 instead of returning [`TransportError::PivResetGlobalFailed`]
    ///    outright: an unverified gate's claim that the mechanism applies here
    ///    was never confirmed, so the failure could just as easily be "wrong
    ///    guess" as "real fault", and [`Self::hid_crescendo_aca_reset_card`]
    ///    only ever fails before it has touched anything (see that method's
    ///    doc), so nothing is lost by trying something else. A `Supported`
    ///    gate skips this: a confirmed-good mechanism failing means something
    ///    is actually wrong, not that the wrong mechanism was tried, so that
    ///    case returns the failure as-is rather than guessing further.
    /// 2. Otherwise (or as the above fallback), [`Self::plan_factory_reset`]
    ///    resolves the PIV-only shape:
    ///    [`FactoryResetPlan::Unsupported`] refuses outright (deliberately
    ///    blocking the PIN and PUK would have no way back);
    ///    [`FactoryResetPlan::NeedsManagementAuth`] authenticates with
    ///    `current` (same `PivResetNeedsManagementAuth` refusal if `None`)
    ///    then sends [`Self::reset`]; [`FactoryResetPlan::Unverified`] sends a
    ///    bare [`Self::reset`] with no pre-blocking; and
    ///    [`FactoryResetPlan::BurnPinPukThenReset`] deliberately exhausts the
    ///    PIN retry counter with wrong values, then the PUK counter, then
    ///    sends RESET (which the card only accepts once BOTH are blocked) —
    ///    the documented decommission path for a card whose PIN/PUK are
    ///    unknown.
    ///
    /// Every path wipes all PIV keys, certificates, and PINs (plus, on the
    /// device-wide path, whatever else that mechanism covers) and leaves the
    /// applet at defaults. [`Self::preview_factory_reset`] resolves which of
    /// the above a caller is about to get *before* any fallback is known to
    /// be needed, read-only, ahead of the call — see its doc for why that's
    /// still the right preview to show even though this method might not
    /// end up matching it exactly.
    pub fn factory_reset(
        &mut self,
        current: Option<CurrentMgmtAuth<'_>>,
    ) -> Result<FactoryResetOutcome, TransportError> {
        use keyroost_piv::compat::FeatureGate;

        let reset_global_gate = self.reset_global_gate();
        if reset_global_gate != FeatureGate::Unsupported {
            let global_current = current.ok_or(TransportError::PivResetNeedsManagementAuth)?;
            match self.hid_crescendo_aca_reset_card(global_current) {
                Ok(outcome) => return Ok(outcome),
                Err(e) if reset_global_gate != FeatureGate::Unverified => {
                    // `Supported`: a confirmed-good mechanism failing is a
                    // real failure, not "wrong mechanism" -- don't go
                    // guessing at a completely different one.
                    return Err(TransportError::PivResetGlobalFailed(Box::new(e)));
                }
                // `Unverified`: this gate's own claim that the device-wide
                // mechanism applies here was never confirmed, so a failure
                // could just as easily mean "wrong guess" as "real fault" --
                // fall through to `PivExtension::Reset`'s own shape below
                // instead of giving up on the one unverified guess.
                // `hid_crescendo_aca_reset_card` only ever returns `Err`
                // before RESET CARD itself has run (see its doc), so nothing
                // was touched by this attempt -- safe to try a completely
                // different mechanism next. Always re-SELECTs PIV before
                // returning, success or failure, so the session is already
                // in the right state for what follows.
                Err(_) => {}
            }
        }

        match self.plan_factory_reset() {
            FactoryResetPlan::Unsupported => return Err(TransportError::PivResetUnsupported),
            FactoryResetPlan::NeedsManagementAuth => {
                let current = current.ok_or(TransportError::PivResetNeedsManagementAuth)?;
                return (|| {
                    self.authenticate_management_current(current)?;
                    self.reset()
                })()
                .map(|()| FactoryResetOutcome::Wiped)
                .map_err(|e| TransportError::PivResetManagementAuthFailed(Box::new(e)));
            }
            FactoryResetPlan::Unverified => {
                return self
                    .reset()
                    .map(|()| FactoryResetOutcome::Wiped)
                    .map_err(|e| TransportError::PivResetUnverifiedFailed(Box::new(e)));
            }
            FactoryResetPlan::BurnPinPukThenReset => self.force_reset(),
        }
    }

    /// Burn the PIV PIN and PUK retry counters and RESET — the documented
    /// decommission path for a card whose PIN/PUK are unknown.
    ///
    /// Tries a bare [`Self::reset`] first, before touching either counter:
    /// if the card accepts it outright (e.g. a previous run already blocked
    /// both and got interrupted before RESET), this succeeds immediately
    /// with nothing further to burn. Only when that bare attempt comes back
    /// [`TransportError::PivResetNotAllowed`] — RESET's `SW_AUTH_BLOCKED` or
    /// `SW_CONDITIONS_NOT_SATISFIED`, meaning the card is enforcing its "PIN
    /// and PUK must already be blocked" precondition — does this fall through
    /// to actually burning
    /// both: deliberately exhaust the PIN retry counter with wrong values,
    /// then the PUK counter, then send RESET again. Any other error from the
    /// bare attempt is returned as-is, with neither counter touched — this
    /// method only starts burning on the strength of the one error it knows
    /// how to fix.
    ///
    /// [`Self::factory_reset`] is what decides this mechanism is the right
    /// one for this fingerprint ([`FactoryResetPlan::BurnPinPukThenReset`])
    /// and calls here; this method itself doesn't consult that plan.
    pub fn force_reset(&mut self) -> Result<FactoryResetOutcome, TransportError> {
        match self.reset() {
            Ok(()) => return Ok(FactoryResetOutcome::Wiped),
            Err(TransportError::PivResetNotAllowed) => {}
            Err(e) => return Err(e),
        }

        // The PIN a successful PUK guess would leave behind: RESET RETRY COUNTER
        // rewrites the PIN when it succeeds, so this has to be a value we can
        // name back to the user (see PivPukGuessAccepted) rather than something
        // random nobody could recover. The PIV default is the friendliest choice.
        const RECOVERY_PIN: &[u8] = b"123456";

        let st = self.status()?;

        // 1. Block the PIN.
        let mut blocked = false;
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..block_attempts_cap(st.pin_retries) {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice()))?;
            match self.verify_pin(&guess) {
                // The guess matched the live PIN: VERIFY changes nothing, it just
                // costs us an attempt that didn't decrement. Draw another.
                Ok(()) => {}
                Err(TransportError::PivPinRejected {
                    tries_remaining: Some(0),
                }) => {
                    blocked = true;
                    break;
                }
                Err(TransportError::PivPinRejected { .. }) => {}
                Err(e) => return Err(e),
            }
            previous = Some(guess);
        }
        if !blocked {
            return Err(TransportError::PivResetIncomplete(
                "the PIV PIN would not report itself blocked within the attempt cap, \
                 so the card was NOT wiped — its keys and certificates are still \
                 there and its PIN retry counter has been spent down. Re-run the \
                 factory reset to finish.",
            ));
        }

        // 2. Block the PUK (via unblock-pin, whose wrong PUK decrements the PUK
        //    counter). Size the loop from the card's real PUK count — `piv
        //    set-retries` can raise it past the default cap, and a loop that
        //    stops short leaves the PIN blocked and the card un-wiped. GET
        //    METADATA is firmware 5.3+, so `None` (the conservative default)
        //    stays the fallback.
        let puk_tries = self
            .metadata(piv::PIN_REF_PUK)
            .and_then(|m| m.retries)
            .map(|(remaining, _total)| remaining);
        let mut puk_blocked = false;
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..block_attempts_cap(puk_tries) {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice()))?;
            match self.unblock_pin(&guess, RECOVERY_PIN) {
                // The guess *was* the PUK, so RESET RETRY COUNTER really ran: the
                // PIN is now RECOVERY_PIN and unblocked. That is a card-state
                // change the user has to be told about, and on cards that restore
                // the retry counter on success the loop would never end.
                Ok(()) => return Err(TransportError::PivPukGuessAccepted),
                Err(TransportError::PivPinRejected {
                    tries_remaining: Some(0),
                }) => {
                    puk_blocked = true;
                    break;
                }
                Err(TransportError::PivPinRejected { .. }) => {}
                Err(e) => return Err(e),
            }
            previous = Some(guess);
        }
        if !puk_blocked {
            return Err(TransportError::PivResetIncomplete(
                "the PIV PUK would not report itself blocked within the attempt cap. \
                 The PIN is now blocked but the card was NOT wiped — re-run the \
                 factory reset to finish, or unblock the PIN with the PUK if you \
                 know it.",
            ));
        }

        // 3. Both blocked — RESET should now succeed. If the card refuses it
        //    for good (the capability pre-check passes on either GET VERSION or
        //    GET SERIAL, so a card can clear it and still have no RESET), say
        //    so honestly: that is the one exit that leaves a card nothing here
        //    can rescue. An unspecific status word is not that exit and keeps
        //    the caller's "re-run the factory reset" hint.
        self.reset()
            .map(|()| FactoryResetOutcome::Wiped)
            .map_err(map_reset_stage_error)
    }

    /// Whether `slot` holds a certificate (GET DATA), and its size if so.
    fn slot_status(&mut self, slot: piv::Slot) -> Result<PivSlotStatus, TransportError> {
        let cert = self.cert_object(slot)?;
        Ok(slot_occupancy(
            slot,
            cert.as_ref().map(Option::as_deref).map_err(|e| *e),
        ))
    }

    /// Transmit one APDU and reassemble a response the card splits across `61xx`
    /// continuations (GET RESPONSE), returning `(payload, sw)`.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        let cmd_sensitive = piv_cmd_sensitive(apdu);
        // GENERAL AUTHENTICATE responses today are only ciphertext (witness /
        // encrypted challenge), but the same INS in signing/decrypt mode
        // returns recovered plaintext — redact uniformly so a future caller
        // can't leak through a trace.
        let resp_sensitive = apdu.get(1) == Some(&0x87);
        // `describe` makes `transmit_applet` bracket every transmitted APDU —
        // the caller's command and each GET RESPONSE / Le-corrected reissue —
        // with a `>` line naming the command and a `<` line reading its status
        // word. The CLI's `--debug` output and the GUI activity log both take
        // this straight from `trace`, so it covers both.
        const IO: crate::AppletIo = crate::AppletIo {
            label: "piv",
            more_data_sw: piv::SW_MORE_DATA,
            get_response: piv::get_response,
            describe: Some(describe_apdu),
        };
        crate::transmit_applet(
            &self.card,
            self.debug,
            &IO,
            apdu,
            cmd_sensitive,
            resp_sensitive,
        )
    }

    /// Transmit an ISO 7816-4 command-chaining sequence (see
    /// [`keyroost_piv::general_auth_sign_chained`] /
    /// [`keyroost_piv::put_data_chained`]): every intermediate chunk must be
    /// accepted with `9000` or the chain aborts; the final chunk's status
    /// word and (already `61xx`-reassembled) response payload are returned
    /// as-is for the caller to interpret. Mirrors
    /// [`OpenPgpSession::transmit_chain`](crate::OpenPgpSession), added here
    /// for the same reason: extended-length rejection ([`Self::sign`],
    /// [`Self::import_certificate`]).
    fn transmit_chain(
        &mut self,
        label: &'static str,
        chunks: &[Vec<u8>],
    ) -> Result<(Vec<u8>, u16), TransportError> {
        let last = chunks.len().saturating_sub(1);
        for (i, chunk) in chunks.iter().enumerate() {
            let (data, sw) = self.transmit_full(chunk)?;
            if i == last {
                return Ok((data, sw));
            }
            // An intermediate chain link the card didn't accept (anything but
            // 9000) aborts the chain.
            if sw != piv::SW_OK {
                return Err(TransportError::Apdu {
                    label,
                    sw1: (sw >> 8) as u8,
                    sw2: sw as u8,
                });
            }
        }
        Ok((Vec::new(), piv::SW_OK)) // unreachable: chunk builders never return an empty list
    }
}

/// Whether a direct (single-APDU) certificate PUT DATA that came back as
/// `result` should be retried with command chaining *because of a PC/SC-layer
/// failure*: only a [`TransportError::Pcsc`] error on an extended-length APDU
/// qualifies. Some reader/card paths fail an extended APDU of a few KB below
/// the card, before any status word; chaining sends short APDUs instead. A
/// status word (success or not) is left to the SW-driven fallback, and every
/// other error propagates.
fn retry_chained_after(result: &Result<(Vec<u8>, u16), TransportError>, extended: bool) -> bool {
    extended && matches!(result, Err(TransportError::Pcsc(_)))
}

/// The status word a chained certificate PUT DATA ended on. `transmit_chain`
/// reports an intermediate chunk's non-`9000` as a generic
/// [`TransportError::Apdu`]; a `6700` or `6A84` there is handed back as a
/// status word instead, so [`cert_write_result`] names it the same way as on
/// the final chunk. Every other error propagates unchanged.
fn chained_cert_sw(result: Result<(Vec<u8>, u16), TransportError>) -> Result<u16, TransportError> {
    match result {
        Ok((_, sw)) => Ok(sw),
        Err(TransportError::Apdu { sw1, sw2, .. })
            if matches!(
                u16::from_be_bytes([sw1, sw2]),
                piv::SW_WRONG_LENGTH | piv::SW_NOT_ENOUGH_MEMORY
            ) =>
        {
            Ok(u16::from_be_bytes([sw1, sw2]))
        }
        Err(e) => Err(e),
    }
}

/// Map the final status word of a certificate PUT DATA: `6700` (wrong
/// length) → [`TransportError::PivCertTooLarge`] with the DER length,
/// `6A84` (not enough memory) → [`TransportError::PivCardFull`], anything
/// else as any PIV write ([`ok_or_write`]).
fn cert_write_result(slot: Slot, len: usize, sw: u16) -> Result<(), TransportError> {
    match sw {
        piv::SW_WRONG_LENGTH => Err(TransportError::PivCertTooLarge { slot, len }),
        piv::SW_NOT_ENOUGH_MEMORY => Err(TransportError::PivCardFull { slot }),
        _ => ok_or_write("piv import certificate", sw),
    }
}

/// Chunk size for the command-chaining fallback, matching the 254-byte chunks
/// [`keyroost-openpgp`](keyroost_openpgp)'s equivalent fallback uses (GnuPG's
/// `exmode = -254`, one byte short of the short-form `Lc` ceiling).
const CHAIN_CHUNK: usize = 254;

/// Whether `apdu` — built by [`piv::general_auth_sign`] or [`piv::put_data`],
/// whose data field is never empty — used extended-length encoding. Both
/// always emit a non-zero short-form `Lc` for a body that fits in one byte,
/// so byte 4 being the `0x00` extended-length marker is unambiguous.
fn uses_extended_length(apdu: &[u8]) -> bool {
    apdu.get(4) == Some(&0x00)
}

/// A short, human-readable name for one of the AIDs/RIDs this crate SELECTs
/// — the standard PIV applet itself (either AID form [`Self::select`] tries)
/// as well as this crate's own fingerprinting probes — for
/// [`describe_apdu`]'s trace label. E.g. `"Feitian RID"` for
/// [`keyroost_piv::fingerprint::FEITIAN_RID`]. `None` for anything else this
/// crate doesn't recognize.
fn known_aid_name(aid: &[u8]) -> Option<&'static str> {
    use keyroost_piv::fingerprint;
    match aid {
        _ if aid == piv::AID_FULL => Some("NIST PIV Card Application"),
        _ if aid == piv::AID => Some("NIST PIV Card Application"),
        _ if aid == fingerprint::FEITIAN_RID => Some("Feitian RID"),
        _ if aid == fingerprint::SWISSBIT_RID => Some("Swissbit RID"),
        _ if aid == fingerprint::IDPRIME_SECONDARY_PIV_AID => Some("IdPrime secondary PIV AID"),
        _ if aid == fingerprint::NITROKEY_ADMIN_AID => Some("Nitrokey admin AID"),
        _ if aid == fingerprint::HID_CRESCENDO_ACA_AID => Some("HID ActivID ACA"),
        _ => None,
    }
}

/// Whether `apdu`'s command body carries secret material and must be
/// redacted from a `--debug` trace ([`crate::dump_cmd`]) — the 5-byte header
/// (CLA INS P1 P2 Lc) stays visible either way. VERIFY (`0x20`), CHANGE
/// REFERENCE DATA (`0x24`), RESET RETRY COUNTER (`0x2C`) carry PINs/PUKs;
/// GENERAL AUTHENTICATE (`0x87`) carries the decrypted witness/challenge;
/// SET MANAGEMENT KEY (`0xFF`) carries the raw new key. The same VERIFY
/// (`0x20`) INS covers HID Crescendo's ACA VERIFY PIN
/// ([`PivSession::verify_pin_hid_crescendo_aca`]) too, just at a different
/// P2 — see [`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_PIN_REF`]. The
/// ACA's own XAUTH sequence adds two more: EXTERNAL AUTHENTICATE (`0x82`)
/// carries the host cryptogram, a value derived from XAUTH key 1 exactly
/// like GENERAL AUTHENTICATE's witness; PUT XAUTH KEY (`0xD8`) carries the
/// raw new key value when it *installs* one — but not when `Lc = 0x04`,
/// HID's documented "delete" short form
/// ([`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove`]),
/// whose body is four fixed, publicly-known bytes with no key material in
/// it at all (see that function's doc) — nothing to redact there, same
/// reasoning as GET CHALLENGE (`0x84`) below. GET CHALLENGE itself is
/// **not** included — its command body is empty and its response is a
/// public nonce, not a secret.
#[must_use]
fn piv_cmd_sensitive(apdu: &[u8]) -> bool {
    match apdu.get(1) {
        Some(0xD8) => apdu.get(4) != Some(&0x04),
        ins => matches!(
            ins,
            Some(0x20) | Some(0x24) | Some(0x2C) | Some(0x87) | Some(0xFF) | Some(0x82)
        ),
    }
}

/// The command-name string that precedes a PIV APDU in a `--debug` /
/// activity-log trace. Resolves `apdu[1]` via [`piv::Instruction`], names the
/// data object GET DATA / PUT DATA is aimed at, names the AID/RID a SELECT
/// targets whenever it's one this crate recognizes (the PIV applet itself,
/// or one of its own fingerprinting probes), sharpens two more cases the INS
/// byte alone leaves ambiguous, separately names HID Crescendo's ACA
/// instructions (not modeled in [`piv::Instruction`] at all, since they
/// aren't PIV), and falls back to the raw INS for anything else this crate
/// never builds.
fn describe_apdu(apdu: &[u8]) -> String {
    let Some(&ins) = apdu.get(1) else {
        return "(malformed APDU)".to_string();
    };
    match piv::Instruction::from_code(ins) {
        // A SELECT's data field is the raw AID/RID itself (no `5C` wrapper,
        // unlike GET DATA / PUT DATA below) — name it whenever it's an AID
        // this crate recognizes; an unrecognized one stays plain `SELECT`.
        Some(piv::Instruction::Select) => match command_data(apdu).and_then(known_aid_name) {
            Some(name) => format!("SELECT ({name})"),
            None => "SELECT".to_string(),
        },
        // GET DATA / PUT DATA both open their body with a `5C <len> <tag>`
        // object selector — name what's being read/written, or show the raw
        // tag when it's one we don't have a name for. (A chained PUT DATA's
        // continuation chunks carry no selector and stay bare.)
        Some(verb @ (piv::Instruction::GetData | piv::Instruction::PutData)) => {
            let verb = verb.name();
            match object_selector_tag(apdu) {
                Some(tag) => {
                    let hex = crate::hex_dump(tag);
                    match piv::data_object_name(tag) {
                        // Raw tag first, then its name — the tag is always shown
                        // so an unfamiliar reader can cross-check the spec.
                        Some(name) => format!("{verb} ({hex} \u{2192} {name})"),
                        None => format!("{verb} ({hex})"),
                    }
                }
                None => verb.to_string(),
            }
        }
        // 0xF6 is MOVE KEY, or DELETE KEY when P1 is the 0xFF sentinel
        // (`piv::delete_key` builds `00 F6 FF <slot>`).
        Some(piv::Instruction::MoveKey) if apdu.get(2) == Some(&0xFF) => {
            "DELETE KEY (yubico extension)".to_string()
        }
        // A bodyless VERIFY (`00 20 00 80`, no Lc) queries the PIN retry
        // counter rather than presenting a PIN.
        Some(piv::Instruction::Verify) if apdu.len() <= 4 => {
            "VERIFY (retry-counter query)".to_string()
        }
        Some(known) => known.name().to_string(),
        // HID Crescendo's ACA (Access Control Applet) instructions — GSC-IS/
        // HID vendor extensions, not PIV at all, so none of the three is
        // modeled in `piv::Instruction` and `from_code` answers `None` for
        // every one of them; matched here by raw INS instead. Naming them
        // keeps a `--debug` trace legible while
        // `authenticate_management_hid_crescendo_aca`/
        // `hid_crescendo_aca_put_xauth_key_op` temporarily switch to the ACA
        // applet, instead of falling through to a bare "INS 0x82"/"INS 0xD8".
        None if ins == 0x84 => "GET CHALLENGE (HID ACA XAUTH)".to_string(),
        None if ins == 0x82 => "EXTERNAL AUTHENTICATE (HID ACA XAUTH)".to_string(),
        // `Lc` alone tells PUT XAUTH KEY's two forms apart: `0x04` is the
        // documented "remove" short form
        // ([`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove`]);
        // every other `Lc` (`0x1D` TDES, `0x15` AES-128) installs a new key
        // ([`keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key`]).
        None if ins == 0xD8 => match apdu.get(4) {
            Some(0x04) => "PUT XAUTH KEY (HID ACA, delete)".to_string(),
            _ => "PUT XAUTH KEY (HID ACA)".to_string(),
        },
        None => format!("INS {ins:#04X}"),
    }
}

/// The data field of an APDU, handling both the short (`Lc` in one byte) and
/// extended (`00 Lc_hi Lc_lo`) length encodings. Any trailing `Le` is ignored.
fn command_data(apdu: &[u8]) -> Option<&[u8]> {
    match apdu.get(4..)? {
        [] => None,
        // Extended length: 0x00 marker, then a two-byte Lc, then the body.
        [0x00, hi, lo, rest @ ..] if !rest.is_empty() => {
            rest.get(..(usize::from(*hi) << 8 | usize::from(*lo)))
        }
        // Short form: one Lc byte, then the body (possibly with a trailing Le).
        [lc, rest @ ..] => rest.get(..usize::from(*lc)).or(Some(rest)),
    }
}

/// The `5C <len> <tag>` object selector at the head of a GET DATA / PUT DATA
/// body, if present.
fn object_selector_tag(apdu: &[u8]) -> Option<&[u8]> {
    match command_data(apdu)? {
        [0x5C, len, rest @ ..] => rest.get(..usize::from(*len)),
        _ => None,
    }
}

/// `KEYROOST_PIV_FORCE_CHAINING` forces the command-chaining path (so the
/// fallback can be exercised on a card that also accepts extended length —
/// mirrors `KEYROOST_OPENPGP_FORCE_CHAINING`).
fn force_chaining() -> bool {
    std::env::var_os("KEYROOST_PIV_FORCE_CHAINING").is_some()
}

/// Whether the connection to `card` negotiated T=0. Fails open: if the
/// status query itself fails, report "not T=0" so behaviour stays exactly
/// what it was before this check existed (extended-length first, status-word
/// fallback second) — a wrong "T=0" answer would silently downgrade every
/// large command on a perfectly good T=1 link.
fn negotiated_t0(card: &Card) -> bool {
    let mut names = [0u8; 256];
    let mut atr = [0u8; pcsc::MAX_ATR_SIZE];
    match card.status2(&mut names, &mut atr) {
        Ok(status) => status.protocol2() == Some(pcsc::Protocol::T0),
        Err(_) => false,
    }
}

/// The chain-up-front decision as a pure function, so the rule is testable
/// without a card: chain when the operator forces it, or when the link is
/// T=0 and therefore cannot carry extended-length APDUs at all.
fn chain_upfront_for(t0: bool, forced: bool) -> bool {
    forced || t0
}

impl PivSession {
    fn chain_upfront(&self) -> bool {
        chain_upfront_for(self.t0, force_chaining())
    }

    fn chain_reason(&self) -> &'static str {
        if force_chaining() {
            "env override"
        } else {
            "T=0 link: extended-length APDUs are not possible on this protocol"
        }
    }
}

/// Turn to-be-signed bytes into the block the card's GENERAL AUTHENTICATE
/// expects: PKCS#1 v1.5 over SHA-256 for RSA (the card does raw RSA), the bare
/// SHA-256/384 digest for ECDSA, and the unhashed message for Ed25519.
fn prepared_block(alg: KeyAlg, tbs: &[u8]) -> Result<Vec<u8>, TransportError> {
    use keyroost_piv::x509::{self, SigHash};
    match x509::signature_hash(alg).map_err(TransportError::X509)? {
        SigHash::Sha256 => {
            let digest = keyroost_proto::sha256::sha256(tbs);
            let rsa_k = match alg {
                KeyAlg::Rsa1024 => Some(128),
                KeyAlg::Rsa2048 => Some(256),
                KeyAlg::Rsa3072 => Some(384),
                KeyAlg::Rsa4096 => Some(512),
                _ => None,
            };
            Ok(match rsa_k {
                Some(k) => x509::pkcs1_v15_sha256(&digest, k),
                None => digest.to_vec(),
            })
        }
        SigHash::Sha384 => Ok(keyroost_proto::sha512::sha384(tbs).to_vec()),
        SigHash::None => Ok(tbs.to_vec()),
    }
}

/// `(algorithm, raw public key)` from a GET METADATA response, only when it
/// actually carries both — the single gate [`PivSession::slot_key`] uses to
/// decide whether a metadata reply is usable or whether to fall back to the
/// session's pubkey cache. Split out as a pure, card-free function (same seam
/// style as [`PubkeyCache`]) so the "is this metadata usable" rule is
/// unit-testable without a card: some PIV implementations answer GET METADATA
/// with `SW_OK` but an empty or partial body for slots they haven't wired
/// reporting up for yet (observed on Nitrokey's `piv-authenticator`, whose
/// `GetMetadata` handler is a stub for every slot but card-authentication) —
/// functionally the same as "no GET METADATA support" for our purposes, not a
/// malformed response worth erroring the caller over.
fn metadata_key_material(md: &Metadata) -> Option<(KeyAlg, &[u8])> {
    let alg = md.algorithm.and_then(KeyAlg::from_id)?;
    let raw = md.public_key.as_deref()?;
    Some((alg, raw))
}

/// The certificate DER inside a `9000` GET DATA body for a slot's cert
/// object: the `0x70` TLV's value. `None` when the body carries no
/// certificate — a `53 00` empty template (Nitrokey's `piv-authenticator`
/// answers a deleted slot this way instead of `6A82`), a `0x53` object with
/// no `0x70`, or a body that isn't a `0x53` data template at all (not
/// expected from a real card, and degraded rather than errored — this feeds
/// read-only status calls). `Err` when there IS a certificate, flagged
/// compressed, that won't inflate — reported as unreadable, never as empty.
/// Pure, so the byte cases stay unit-tested.
fn cert_object_der(body: &[u8]) -> Result<Option<Vec<u8>>, CertUnreadable> {
    let Some((der, gzip)) = piv::unwrap_data_object(body)
        .ok()
        .and_then(piv::cert_object_parts)
    else {
        return Ok(None);
    };
    if gzip {
        // The object holds the cert gzip-compressed (CertInfo bit 0, which
        // the writing tool chose). Inflate it before anyone parses it as DER;
        // never hand the compressed bytes on.
        gunzip_capped(der).map(Some)
    } else {
        Ok(Some(der.to_vec()))
    }
}

/// A slot's [`PivSlotStatus`] from its decoded certificate object: present
/// (with its DER byte length) when non-empty, present-but-unreadable when a
/// certificate is there that won't decode, absent otherwise.
fn slot_occupancy(slot: piv::Slot, cert: Result<Option<&[u8]>, CertUnreadable>) -> PivSlotStatus {
    match cert {
        Err(reason) => PivSlotStatus {
            slot,
            cert_present: true,
            cert_len: 0,
            cert_unreadable: Some(reason),
        },
        Ok(der) => {
            let len = der.map_or(0, <[u8]>::len);
            PivSlotStatus {
                slot,
                cert_present: len > 0,
                cert_len: len,
                cert_unreadable: None,
            }
        }
    }
}

/// Decode the public key carried in GET METADATA tag `0x04`. Yubico encodes it
/// as the same TLVs a GENERATE response carries — observed both with and
/// without the outer `7F49` template across firmware, so accept either shape.
fn public_key_from_metadata(raw: &[u8]) -> Result<PublicKey, keyroost_piv::ParseError> {
    if raw.starts_with(&[0x7F, 0x49]) {
        return piv::parse_public_key(raw);
    }
    // Bare inner TLVs: 86 (EC point) or 81/82 (RSA modulus/exponent).
    if let Some(point) = piv::find_tlv(raw, 0x86) {
        return Ok(PublicKey::Ecc {
            point: point.to_vec(),
        });
    }
    match (piv::find_tlv(raw, 0x81), piv::find_tlv(raw, 0x82)) {
        (Some(m), Some(e)) => Ok(PublicKey::Rsa {
            modulus: m.to_vec(),
            exponent: e.to_vec(),
        }),
        _ => Err(keyroost_piv::ParseError::NotPublicKey),
    }
}

/// Constant-time slice equality (fold-XOR; no early exit on the bytes).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Map a PIV status word to success or a labelled APDU error.
fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// Like [`ok_or_apdu`] but maps the "security status not satisfied" word a write
/// returns when management-key auth or the PIN hasn't been presented.
fn ok_or_write(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_SECURITY_NOT_SATISFIED {
        Err(TransportError::PivSecurityNotSatisfied)
    } else {
        ok_or_apdu(label, sw)
    }
}

/// Map a PIN/PUK-verification status word: `9000` ok, `63 Cx` / `6983` rejected
/// with the remaining-try count, anything else a generic APDU error.
fn map_pin_sw(sw: u16) -> Result<(), TransportError> {
    if sw == piv::SW_OK {
        Ok(())
    } else if let Some(n) = crate::sw_tries_remaining(sw) {
        Err(TransportError::PivPinRejected {
            tries_remaining: Some(n),
        })
    } else if sw == piv::SW_AUTH_BLOCKED {
        Err(TransportError::PivPinRejected {
            tries_remaining: Some(0),
        })
    } else {
        Err(TransportError::Apdu {
            label: "piv pin/puk",
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// What [`block_crypt`] should do with a block.
#[derive(Clone, Copy)]
enum CryptOp {
    Encrypt,
    Decrypt,
}

/// AES / 3DES ECB single-block (or block-aligned) transform for the
/// management-key witness/challenge round. `data` must be a non-empty multiple
/// of the cipher block size — the witness comes from the card, and an unaligned
/// length would otherwise panic in the block conversion below.
fn block_crypt(
    alg: MgmtAlg,
    key: &[u8],
    data: &[u8],
    op: CryptOp,
) -> Result<Vec<u8>, TransportError> {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    if data.is_empty() || data.len() % alg.block_size() != 0 {
        return Err(TransportError::MalformedResponse(
            "PIV witness/challenge length is not a whole cipher block",
        ));
    }

    fn run<C: BlockEncrypt + BlockDecrypt>(c: &C, data: &[u8], op: CryptOp, bs: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(bs) {
            let mut block = GenericArray::clone_from_slice(chunk);
            match op {
                CryptOp::Encrypt => c.encrypt_block(&mut block),
                CryptOp::Decrypt => c.decrypt_block(&mut block),
            }
            out.extend_from_slice(&block);
        }
        out
    }

    let bad = |_| TransportError::PivBadKeyLength;
    match alg {
        MgmtAlg::TripleDes => {
            let c = des::TdesEde3::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 8))
        }
        MgmtAlg::Aes128 => {
            let c = aes::Aes128::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
        MgmtAlg::Aes192 => {
            let c = aes::Aes192::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
        MgmtAlg::Aes256 => {
            let c = aes::Aes256::new_from_slice(key).map_err(bad)?;
            Ok(run(&c, data, op, 16))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gzip::MAX_CERT_DECOMPRESSED;

    #[test]
    fn decode_serial_if_bcd_applies_only_when_the_quirk_resolves() {
        use keyroost_piv::fingerprint::AppletFingerprint;

        // Token2 carries `InsF8SerialIsBcd` for any reported applet version
        // (see `keyroost_piv::compat`'s `QUIRKS_BY_APPLET_TABLE`) — 0x1234
        // read as packed BCD is decimal 1234.
        assert_eq!(
            decode_serial_if_bcd(AppletFingerprint::Token2, Some(&[1, 0]), None, Some(0x1234)),
            Some(1234)
        );
        // No applet_version → nothing to version-match, so the quirk never
        // resolves and the serial passes through unchanged.
        assert_eq!(
            decode_serial_if_bcd(AppletFingerprint::Token2, None, None, Some(0x1234)),
            Some(0x1234)
        );
        // A fingerprint with no quirk-table entry at all: unchanged.
        assert_eq!(
            decode_serial_if_bcd(
                AppletFingerprint::YubiKey,
                Some(&[5, 7]),
                None,
                Some(0x1234)
            ),
            Some(0x1234)
        );
        // No serial to begin with: still `None`, quirk or not.
        assert_eq!(
            decode_serial_if_bcd(AppletFingerprint::Token2, Some(&[1, 0]), None, None),
            None
        );
    }

    #[test]
    fn clear_metadata_if_quirky_strips_algorithm_and_public_key_together() {
        use keyroost_piv::compat::PivQuirk;

        let md = Metadata {
            algorithm: Some(0x07),
            policy: Some((0x01, 0x02)),
            origin: Some(1),
            public_key: Some(vec![0xAB, 0xCD]),
            is_default: Some(false),
            retries: None,
        };

        // The quirk active: algorithm and public key are gone, every other
        // field survives untouched.
        let quirky = BTreeSet::from([PivQuirk::InsF7MetadataAlgorithmInvalid]);
        let cleared = clear_metadata_if_quirky(&quirky, md.clone());
        assert_eq!(
            cleared,
            Metadata {
                algorithm: None,
                public_key: None,
                ..md.clone()
            }
        );

        // No quirk active (empty set, or a set with an unrelated quirk):
        // passed through unchanged.
        assert_eq!(clear_metadata_if_quirky(&BTreeSet::new(), md.clone()), md);
        let other = BTreeSet::from([PivQuirk::InsF8SerialIsBcd]);
        assert_eq!(clear_metadata_if_quirky(&other, md.clone()), md);
    }

    #[test]
    fn describe_apdu_names_the_command() {
        assert_eq!(
            describe_apdu(&piv::select_full()),
            "SELECT (NIST PIV Card Application)"
        );
        // The short RID-only PIV AID names the same application.
        assert_eq!(
            describe_apdu(&piv::select()),
            "SELECT (NIST PIV Card Application)"
        );
        assert_eq!(
            describe_apdu(&piv::get_version()),
            "GET VERSION (yubico extension)"
        );
        // GET DATA / PUT DATA name the object in their 5C selector; an
        // unknown tag falls back to raw hex; both length encodings parse.
        assert_eq!(
            describe_apdu(&piv::get_data(&Slot::Authentication.cert_object_tag())),
            "GET DATA (5F C1 05 \u{2192} X.509 Certificate for PIV Authentication)"
        );
        assert_eq!(
            describe_apdu(&piv::get_data(&[0x5F, 0xC1, 0x99])),
            "GET DATA (5F C1 99)"
        );
        assert_eq!(
            describe_apdu(&piv::put_data(
                &Slot::Signature.cert_object_tag(),
                &[0x53, 0x00]
            )),
            "PUT DATA (5F C1 0A \u{2192} X.509 Certificate for Digital Signature)"
        );
        assert_eq!(
            describe_apdu(&piv::put_data_chained(&[0x5F, 0xC1, 0x0C], &[0x01], 254)[0]),
            "PUT DATA (5F C1 0C \u{2192} Key History Object)"
        );
        // 0xF6 with the P1 == 0xFF sentinel is DELETE, not MOVE.
        assert_eq!(
            describe_apdu(&piv::delete_key(Slot::Signature)),
            "DELETE KEY (yubico extension)"
        );
        assert_eq!(
            describe_apdu(&piv::move_key(Slot::Retired(1), Slot::Authentication)),
            "MOVE KEY (yubico extension)"
        );
        // Bodyless VERIFY is a retry-counter query.
        assert_eq!(
            describe_apdu(&piv::verify_pin_status()),
            "VERIFY (retry-counter query)"
        );
        assert!(describe_apdu(&piv::verify_pin(b"12345678").unwrap()).starts_with("VERIFY"));
        // Unknown / malformed fall back rather than panic.
        assert_eq!(describe_apdu(&[0x00, 0x99, 0x00, 0x00]), "INS 0x99");
        assert_eq!(describe_apdu(&[]), "(malformed APDU)");
    }

    #[test]
    fn describe_apdu_names_fingerprinting_probe_aids() {
        assert_eq!(
            describe_apdu(&piv::select_by_aid(&keyroost_piv::fingerprint::FEITIAN_RID)),
            "SELECT (Feitian RID)"
        );
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::SWISSBIT_RID
            )),
            "SELECT (Swissbit RID)"
        );
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::IDPRIME_SECONDARY_PIV_AID
            )),
            "SELECT (IdPrime secondary PIV AID)"
        );
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::NITROKEY_ADMIN_AID
            )),
            "SELECT (Nitrokey admin AID)"
        );
        // An AID none of the probes use stays plain, unlabeled SELECT.
        assert_eq!(
            describe_apdu(&piv::select_by_aid(&[0xA0, 0x00, 0x00, 0x00, 0x03])),
            "SELECT"
        );
    }

    #[test]
    fn describe_apdu_names_the_hid_aca_select() {
        // Not a fingerprinting probe like the AIDs above — the ACA instance
        // `authenticate_management_hid_crescendo_aca`/
        // `hid_crescendo_aca_put_xauth_key_op` temporarily SELECT into for
        // the XAUTH unlock / PUT XAUTH KEY sequence, so a trace reader can
        // tell it apart from an unrecognized SELECT at a glance.
        assert_eq!(
            describe_apdu(&piv::select_by_aid(
                &keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID
            )),
            "SELECT (HID ActivID ACA)"
        );
    }

    #[test]
    fn describe_apdu_names_the_hid_aca_xauth_instructions() {
        // GET CHALLENGE and EXTERNAL AUTHENTICATE aren't PIV at all — not
        // modeled in `piv::Instruction` — so without this they'd fall
        // through to a bare "INS 0x84"/"INS 0x82".
        assert_eq!(
            describe_apdu(&keyroost_piv::fingerprint::HID_CRESCENDO_ACA_GET_CHALLENGE),
            "GET CHALLENGE (HID ACA XAUTH)"
        );
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_aca_external_authenticate(&[0xAAu8; 8])
            ),
            "EXTERNAL AUTHENTICATE (HID ACA XAUTH)"
        );
        // PUT XAUTH KEY's two forms are told apart by Lc alone: installing a
        // key (any algorithm) vs. HID's documented Lc=04h "delete" form.
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key(
                    MgmtAlg::TripleDes,
                    &[0u8; 24]
                )
                .unwrap()
            ),
            "PUT XAUTH KEY (HID ACA)"
        );
        assert_eq!(
            describe_apdu(
                &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key(
                    MgmtAlg::Aes128,
                    &[0u8; 16]
                )
                .unwrap()
            ),
            "PUT XAUTH KEY (HID ACA)"
        );
        assert_eq!(
            describe_apdu(&keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove()),
            "PUT XAUTH KEY (HID ACA, delete)"
        );
    }

    #[test]
    fn piv_cmd_sensitive_covers_every_secret_bearing_ins_including_hid_aca() {
        // Secret-bearing: PINs/PUKs, GENERAL AUTHENTICATE, SET MANAGEMENT
        // KEY, and the two HID ACA instructions that carry key-derived or
        // raw key material.
        for ins in [0x20u8, 0x24, 0x2C, 0x87, 0xFF, 0x82, 0xD8] {
            assert!(
                piv_cmd_sensitive(&[0x00, ins, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]),
                "INS {ins:#04X} should be redacted"
            );
        }
        // GET CHALLENGE: empty body, public-nonce response — nothing to hide.
        assert!(!piv_cmd_sensitive(
            &keyroost_piv::fingerprint::HID_CRESCENDO_ACA_GET_CHALLENGE
        ));
        // An unrelated INS (SELECT) is never sensitive either.
        assert!(!piv_cmd_sensitive(&piv::select_full()));
        // A real PUT XAUTH KEY install still redacts its body...
        assert!(piv_cmd_sensitive(
            &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key(
                MgmtAlg::TripleDes,
                &[0u8; 24]
            )
            .unwrap()
        ));
        // ...but the Lc=04h "delete" form carries no key material at all —
        // four fixed, publicly-known bytes — so it must not be redacted.
        assert!(!piv_cmd_sensitive(
            &keyroost_piv::fingerprint::hid_crescendo_aca_put_xauth_key_remove()
        ));
    }

    #[test]
    fn mgmt_algs_for_key_len_disambiguates_by_length() {
        use MgmtAlg::*;
        // Unique lengths pin a single algorithm.
        assert_eq!(mgmt_algs_for_key_len(16), &[Aes128]);
        assert_eq!(mgmt_algs_for_key_len(32), &[Aes256]);
        // 24 bytes fits both 3DES and AES-192 — 3DES first (the historical
        // pre-GET-METADATA default), then the P1 probe decides.
        assert_eq!(mgmt_algs_for_key_len(24), &[TripleDes, Aes192]);
        // Every candidate's own key_len() must round-trip back to a list that
        // contains it — the table and MgmtAlg::key_len() must not drift apart.
        for alg in [TripleDes, Aes128, Aes192, Aes256] {
            assert!(mgmt_algs_for_key_len(alg.key_len()).contains(&alg));
        }
        // Nothing plausible-looking (single-DES) or absurd resolves.
        assert!(mgmt_algs_for_key_len(8).is_empty());
        assert!(mgmt_algs_for_key_len(0).is_empty());
        assert!(mgmt_algs_for_key_len(20).is_empty());
    }

    #[test]
    fn pick_mgmt_alg_narrows_probe_results_by_length() {
        use MgmtAlg::*;

        // One probe accepted, right length -> that one.
        assert_eq!(pick_mgmt_alg(&[Aes128], 16), Some(Aes128));
        // One probe accepted, wrong length for the key in hand -> nothing.
        assert_eq!(pick_mgmt_alg(&[Aes256], 24), None);

        // A lax card accepts every P1. The 24-byte key narrows it to 3DES +
        // AES-192, and 3DES wins the tie.
        assert_eq!(
            pick_mgmt_alg(&[TripleDes, Aes128, Aes192, Aes256], 24),
            Some(TripleDes)
        );
        // Same lax card, 16-byte key -> unambiguously AES-128.
        assert_eq!(
            pick_mgmt_alg(&[TripleDes, Aes128, Aes192, Aes256], 16),
            Some(Aes128)
        );
        // 24-byte key, but only AES-192 was accepted -> no 3DES to prefer.
        assert_eq!(pick_mgmt_alg(&[Aes192], 24), Some(Aes192));
        // 24-byte key, both 24-byte algs accepted but in the other order ->
        // still 3DES (preference, not position).
        assert_eq!(pick_mgmt_alg(&[Aes192, TripleDes], 24), Some(TripleDes));

        // Empty accepted set = probe learned nothing -> fall back to length
        // alone (same as the pre-probe behaviour).
        assert_eq!(pick_mgmt_alg(&[], 16), Some(Aes128));
        assert_eq!(pick_mgmt_alg(&[], 24), Some(TripleDes));
        assert_eq!(pick_mgmt_alg(&[], 32), Some(Aes256));
        assert_eq!(pick_mgmt_alg(&[], 20), None);
    }

    // --- pubkey-cache invalidation semantics ---------------------------------
    //
    // The session methods that drive these transitions need a live card, so
    // what gets pinned here is the PubkeyCache transition each of them is a
    // one-line caller of. What these defend: on metadata-less firmware the
    // cache is the ONLY source for CSR/self-sign key material, so a stale
    // entry silently produces a certificate whose SPKI doesn't match the
    // private key on the card.

    fn ecc(byte: u8) -> PublicKey {
        PublicKey::Ecc {
            point: vec![0x04, byte],
        }
    }

    fn rsa(byte: u8) -> PublicKey {
        PublicKey::Rsa {
            modulus: vec![byte],
            exponent: vec![0x01, 0x00, 0x01],
        }
    }

    #[test]
    fn pubkey_cache_starts_empty_and_remember_seeds_exactly_one_slot() {
        // A fresh open() has nothing to fall back to — there is deliberately
        // no on-disk or cross-process persistence.
        let mut cache = PubkeyCache::new();
        assert!(cache.0.is_empty());
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        assert_eq!(cache.0.len(), 1);
        assert_eq!(cache.get(0x9A), Some(&(KeyAlg::EccP256, ecc(1))));
        // Seeding 9A says nothing about any other slot.
        assert_eq!(cache.get(0x9C), None);
    }

    #[test]
    fn remember_replaces_the_slots_previous_entry() {
        // generate_key over an occupied slot mints a new keypair: the old
        // cached pubkey must not survive to describe the new private key.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9A, KeyAlg::Rsa2048, rsa(2));
        assert_eq!(cache.0.len(), 1);
        assert_eq!(cache.get(0x9A), Some(&(KeyAlg::Rsa2048, rsa(2))));
    }

    #[test]
    fn evict_forgets_only_the_deleted_slot() {
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9C, KeyAlg::EccP384, ecc(2));
        cache.evict(0x9A);
        // The deleted slot's key material is gone from the card; a bystander
        // slot's entry is still good.
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.get(0x9C), Some(&(KeyAlg::EccP384, ecc(2))));
        // Deleting a slot this session never cached is a quiet no-op.
        cache.evict(0x82);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn migrate_carries_the_entry_and_leaves_nothing_at_src() {
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9C, KeyAlg::EccP384, ecc(2));
        cache.migrate(0x9A, 0x82);
        // The key relocated: its entry follows it to dest — that's what keeps
        // CSR/self-sign working at dest on metadata-less firmware — and src
        // no longer holds anything to describe.
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.get(0x82), Some(&(KeyAlg::EccP256, ecc(1))));
        // A bystander slot is untouched.
        assert_eq!(cache.get(0x9C), Some(&(KeyAlg::EccP384, ecc(2))));
    }

    #[test]
    fn migrate_of_an_uncached_src_changes_nothing() {
        // Moving a key this session never generated: there is nothing to
        // carry, and crucially nothing gets invented at dest.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9C, KeyAlg::EccP384, ecc(2));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x82), None);
        assert_eq!(cache.get(0x9C), Some(&(KeyAlg::EccP384, ecc(2))));
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn migrate_replaces_a_stale_dest_entry() {
        // The card refuses MOVE KEY into an occupied slot, so any dest entry
        // present here is stale by definition (e.g. remember_pubkey of a slot
        // that was later emptied out-of-session) — the key that actually
        // arrived must win.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x82, KeyAlg::EccP384, ecc(9));
        cache.migrate(0x9A, 0x82);
        assert_eq!(cache.get(0x82), Some(&(KeyAlg::EccP256, ecc(1))));
        assert_eq!(cache.get(0x9A), None);
        assert_eq!(cache.0.len(), 1);
    }

    #[test]
    fn clear_wipes_every_slot() {
        // reset() factory-wipes the applet, and factory_reset funnels into the
        // same reset() at the end of its path — both end here, with no
        // survivors for any slot.
        let mut cache = PubkeyCache::new();
        cache.remember(0x9A, KeyAlg::EccP256, ecc(1));
        cache.remember(0x9C, KeyAlg::Rsa2048, rsa(2));
        cache.remember(0x82, KeyAlg::Ed25519, ecc(3));
        cache.clear();
        assert!(cache.0.is_empty());
    }

    // --- metadata-vs-cache fallback gate ---------------------------------
    //
    // `slot_key` treats GET METADATA as usable only when it actually names
    // both the algorithm and the public key; anything short of that (empty,
    // algorithm-only, pubkey-only — e.g. Nitrokey's piv-authenticator, whose
    // GetMetadata handler is a stub for every slot but card-authentication
    // and answers SW_OK with nothing) must fall through to the pubkey cache
    // instead of erroring the caller.

    #[test]
    fn metadata_with_neither_field_is_not_usable() {
        // The stub-firmware case: SW_OK, empty body.
        assert_eq!(metadata_key_material(&Metadata::default()), None);
    }

    #[test]
    fn metadata_with_only_algorithm_is_not_usable() {
        let md = Metadata {
            algorithm: Some(KeyAlg::EccP256.id()),
            ..Metadata::default()
        };
        assert_eq!(metadata_key_material(&md), None);
    }

    #[test]
    fn metadata_with_only_public_key_is_not_usable() {
        let md = Metadata {
            public_key: Some(vec![0x86, 0x01, 0x04]),
            ..Metadata::default()
        };
        assert_eq!(metadata_key_material(&md), None);
    }

    #[test]
    fn metadata_with_an_unrecognized_algorithm_id_is_not_usable() {
        // A byte GET METADATA reported that this crate's KeyAlg doesn't cover.
        let md = Metadata {
            algorithm: Some(0xFF),
            public_key: Some(vec![0x86, 0x01, 0x04]),
            ..Metadata::default()
        };
        assert_eq!(metadata_key_material(&md), None);
    }

    #[test]
    fn metadata_with_both_fields_is_usable() {
        let md = Metadata {
            algorithm: Some(KeyAlg::EccP256.id()),
            public_key: Some(vec![0x86, 0x01, 0x04]),
            ..Metadata::default()
        };
        assert_eq!(
            metadata_key_material(&md),
            Some((KeyAlg::EccP256, &[0x86, 0x01, 0x04][..]))
        );
    }

    // --- certificate DER out of a GET DATA reply --------------------------
    //
    // `cert_object_der` is what `read_certificate` (and, through it,
    // `slot_status` / `status_detailed`) uses to decide whether a slot holds
    // a certificate. The regression this guards: a deleted slot answering
    // SW_OK with an empty `53 00` template (Nitrokey's piv-authenticator,
    // observed with `piv status` after `piv delete-cert`) must read as empty,
    // not "cert present (0 bytes)".

    #[test]
    fn cert_object_der_empty_template_is_none() {
        // `53 00`: object present, zero-length value — the Nitrokey case.
        assert_eq!(cert_object_der(&[0x53, 0x00]), Ok(None));
    }

    #[test]
    fn cert_object_der_populated_template_yields_the_inner_value() {
        // `53 03 70 01 AB`: a (fake, minimal) `70` TLV wrapping one byte,
        // CertInfo absent so it reads as uncompressed and passes through.
        assert_eq!(
            cert_object_der(&[0x53, 0x03, 0x70, 0x01, 0xAB]),
            Ok(Some(vec![0xAB]))
        );
    }

    /// gzip-wrap `payload` (minimal RFC 1952 header, raw-DEFLATE body, and
    /// the real CRC32 + ISIZE trailer the reader verifies).
    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        v.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, 6));
        v.extend_from_slice(&crate::gzip::crc32(payload).to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v
    }

    #[test]
    fn gunzip_capped_round_trips() {
        let der = b"\x30\x82\x01\x0a hello certificate bytes";
        assert_eq!(gunzip_capped(&gzip(der)).as_deref(), Ok(&der[..]));
        // Not gzip -> Damaged, no panic.
        assert_eq!(
            gunzip_capped(b"\x30\x03\x01\x01\xff"),
            Err(CertUnreadable::Damaged)
        );
        assert_eq!(gunzip_capped(&[]), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_inflates_a_gzip_compressed_cert() {
        // The exact shape that broke #147: CertInfo 0x01 (gzip) with the cert
        // stored compressed. cert_object_der must return the ORIGINAL DER.
        let der = b"\x30\x82\x01\x0a a yubikey attestation cert (stand-in)";
        let gz = gzip(der);
        // Build 53 { 70 <gz> 71 01 01 FE 00 } with short-form lengths.
        assert!(gz.len() < 0x80, "test vector must stay short-form");
        let mut inner = vec![0x70, gz.len() as u8];
        inner.extend_from_slice(&gz);
        inner.extend_from_slice(&[0x71, 0x01, 0x01, 0xFE, 0x00]);
        let mut obj = vec![0x53, inner.len() as u8];
        obj.extend_from_slice(&inner);
        assert_eq!(cert_object_der(&obj), Ok(Some(der.to_vec())));
    }

    /// `53 { 70 <payload> 71 01 01 FE 00 }` — a cert object flagged
    /// gzip-compressed, with long-form lengths so large payloads fit.
    fn compressed_cert_object(payload: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
            let n = val.len();
            let mut v = vec![tag];
            match n {
                0..=0x7F => v.push(n as u8),
                0x80..=0xFF => v.extend_from_slice(&[0x81, n as u8]),
                _ => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
            }
            v.extend_from_slice(val);
            v
        }
        let mut inner = tlv(0x70, payload);
        inner.extend_from_slice(&[0x71, 0x01, 0x01, 0xFE, 0x00]);
        tlv(0x53, &inner)
    }

    // A slot whose certificate is flagged compressed but will not inflate
    // holds *something* — it must read as unreadable, never as empty, so
    // `piv status` doesn't invite overwriting it and `export-cert` doesn't
    // report "no certificate" (#147 follow-up; seen on a YubiKey 5.7).

    #[test]
    fn cert_object_der_flagged_compressed_but_not_gzip_is_damaged() {
        let obj = compressed_cert_object(b"\x30\x82\x01\x0a plain DER, wrongly flagged");
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_invalid_deflate_body_is_damaged() {
        // A gzip header, then a DEFLATE block of reserved type (BTYPE = 11),
        // which no decoder accepts, then the 8-byte trailer.
        let mut gz = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        gz.extend_from_slice(&[0x07, 0x00, 0x00]);
        gz.extend_from_slice(&[0u8; 8]);
        let obj = compressed_cert_object(&gz);
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_truncated_gzip_is_damaged() {
        let der: Vec<u8> = (0..400u32).map(|i| (i * 7 % 251) as u8).collect();
        let gz = gzip(&der);
        let obj = compressed_cert_object(&gz[..gz.len() / 2]);
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::Damaged));
    }

    #[test]
    fn cert_object_der_over_the_inflate_cap_is_too_large() {
        let obj = compressed_cert_object(&gzip(&vec![0u8; MAX_CERT_DECOMPRESSED + 1]));
        assert_eq!(cert_object_der(&obj), Err(CertUnreadable::TooLarge));
    }

    #[test]
    fn cert_object_der_exactly_at_the_inflate_cap_is_read() {
        let der = vec![0u8; MAX_CERT_DECOMPRESSED];
        let obj = compressed_cert_object(&gzip(&der));
        assert_eq!(cert_object_der(&obj), Ok(Some(der)));
    }

    #[test]
    fn slot_occupancy_marks_an_unreadable_cert_present_not_empty() {
        let occ = slot_occupancy(piv::Slot::KeyManagement, Err(CertUnreadable::Damaged));
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, 0);
        assert_eq!(occ.cert_unreadable, Some(CertUnreadable::Damaged));
        let ok = slot_occupancy(piv::Slot::KeyManagement, Ok(Some(&[0xAB][..])));
        assert_eq!(ok.cert_unreadable, None);
    }

    #[test]
    fn unreadable_cert_error_names_the_slot_and_the_reason() {
        let e = TransportError::PivCertUnreadable {
            slot: piv::Slot::KeyManagement,
            reason: CertUnreadable::Damaged,
        };
        let msg = e.to_string();
        assert!(msg.contains(&piv::Slot::KeyManagement.label()), "{msg}");
        assert!(msg.contains("compressed data is damaged"), "{msg}");
        let e = TransportError::PivCertUnreadable {
            slot: piv::Slot::KeyManagement,
            reason: CertUnreadable::TooLarge,
        };
        assert!(e.to_string().contains("64 KiB"), "{e}");
    }

    #[test]
    fn a_pcsc_failure_of_an_extended_apdu_retries_chained() {
        let pcsc = Err(TransportError::Pcsc(pcsc::Error::NotTransacted));
        assert!(retry_chained_after(&pcsc, true));
        // A short APDU has nothing to gain from chaining.
        assert!(!retry_chained_after(&pcsc, false));
        // Any other error propagates.
        assert!(!retry_chained_after(
            &Err(TransportError::HostRngFailed),
            true
        ));
        // A status word, success or not, is the SW-driven fallback's call.
        assert!(!retry_chained_after(&Ok((Vec::new(), piv::SW_OK)), true));
        assert!(!retry_chained_after(&Ok((Vec::new(), 0x6700)), true));
    }

    #[test]
    fn cert_write_status_names_too_large_and_card_full() {
        let slot = piv::Slot::Signature;
        assert!(matches!(
            cert_write_result(slot, 3087, piv::SW_WRONG_LENGTH),
            Err(TransportError::PivCertTooLarge { len: 3087, .. })
        ));
        assert!(matches!(
            cert_write_result(slot, 3087, piv::SW_NOT_ENOUGH_MEMORY),
            Err(TransportError::PivCardFull { .. })
        ));
        assert!(cert_write_result(slot, 10, piv::SW_OK).is_ok());
        assert!(matches!(
            cert_write_result(slot, 10, piv::SW_SECURITY_NOT_SATISFIED),
            Err(TransportError::PivSecurityNotSatisfied)
        ));
    }

    #[test]
    fn a_mid_chain_length_or_memory_refusal_reaches_the_cert_mapping() {
        let apdu = |sw1, sw2| {
            Err(TransportError::Apdu {
                label: "piv import certificate",
                sw1,
                sw2,
            })
        };
        assert_eq!(chained_cert_sw(apdu(0x67, 0x00)).ok(), Some(0x6700));
        assert_eq!(chained_cert_sw(apdu(0x6A, 0x84)).ok(), Some(0x6A84));
        assert_eq!(chained_cert_sw(Ok((Vec::new(), 0x9000))).ok(), Some(0x9000));
        // Other intermediate refusals keep their generic error.
        assert!(matches!(
            chained_cert_sw(apdu(0x69, 0x82)),
            Err(TransportError::Apdu { sw1: 0x69, .. })
        ));
    }

    #[test]
    fn too_large_and_card_full_errors_name_the_slot_and_size() {
        let slot = piv::Slot::Signature;
        let msg = TransportError::PivCertTooLarge { slot, len: 3087 }.to_string();
        assert!(msg.contains(&slot.label()), "{msg}");
        assert!(msg.contains("3087 bytes"), "{msg}");
        assert!(msg.contains("too large"), "{msg}");
        let msg = TransportError::PivCardFull { slot }.to_string();
        assert!(msg.contains(&slot.label()), "{msg}");
        assert!(msg.contains("no room left"), "{msg}");
    }

    #[test]
    fn cert_object_der_template_without_70_is_none() {
        // `53 02 71 00`: a `0x53` object carrying only a cert-info `71` TLV.
        assert_eq!(cert_object_der(&[0x53, 0x02, 0x71, 0x00]), Ok(None));
    }

    #[test]
    fn cert_object_der_unparseable_body_is_none_not_a_panic() {
        // Not a `0x53` template at all — shouldn't happen on a real card, but
        // a read-only status call must degrade gracefully, not panic or error.
        assert_eq!(cert_object_der(&[0xFF, 0x00]), Ok(None));
    }

    #[test]
    fn slot_occupancy_reads_present_only_for_a_non_empty_cert() {
        let slot = piv::Slot::Authentication;
        assert!(!slot_occupancy(slot, Ok(None)).cert_present);
        assert!(!slot_occupancy(slot, Ok(Some(&[]))).cert_present);
        let occ = slot_occupancy(slot, Ok(Some(&[0xAB, 0xCD])));
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, 2);
    }

    // --- cert_len is the DER length, not the `0x53` object's value length -
    //
    // `PivSlotStatus::cert_len` documents the certificate's DER length as
    // read from the card, not the size of the object wrapping it. These
    // pin that end-to-end through the same two pure helpers `read_certificate`
    // and `status_detailed` share: `cert_object_der` (strip the framing) then
    // `slot_occupancy` (measure what's left).

    #[test]
    fn slot_occupancy_cert_len_is_der_length_not_object_length() {
        // `53 <len> 70 <len> <der> 71 01 00 FE 00`: a YubiKey-shaped object —
        // DER wrapped in `70`, followed by the `71` CertInfo and `FE`
        // error-detection TLVs. `cert_len` must be the DER's own length (4),
        // not the larger `70`..`FE` object span.
        let der = [0xAA, 0xBB, 0xCC, 0xDD];
        let inner = [
            0x70, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // `70` cert DER
            0x71, 0x01, 0x00, // CertInfo
            0xFE, 0x00, // error detection
        ];
        let mut body = vec![0x53, inner.len() as u8];
        body.extend_from_slice(&inner);

        let cert_der = cert_object_der(&body);
        assert_eq!(cert_der, Ok(Some(der.to_vec())));
        let occ = slot_occupancy(
            piv::Slot::Authentication,
            cert_der.as_ref().map(Option::as_deref).map_err(|e| *e),
        );
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, der.len());
    }

    #[test]
    fn slot_occupancy_cert_len_is_der_length_when_71_and_fe_are_absent() {
        // `53 <len> 70 <len> <der>`: some non-YubiKey PIV applets omit the
        // `71`/`FE` TLVs entirely. `cert_len` is still just the DER length.
        let der = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut inner = vec![0x70, der.len() as u8];
        inner.extend_from_slice(&der);
        let mut body = vec![0x53, inner.len() as u8];
        body.extend_from_slice(&inner);

        let cert_der = cert_object_der(&body);
        assert_eq!(cert_der, Ok(Some(der.to_vec())));
        let occ = slot_occupancy(
            piv::Slot::Authentication,
            cert_der.as_ref().map(Option::as_deref).map_err(|e| *e),
        );
        assert!(occ.cert_present);
        assert_eq!(occ.cert_len, der.len());
    }

    #[test]
    fn block_attempts_cap_exceeds_reported_but_is_bounded() {
        // A card reporting 3 tries: we try a few more than 3 to guarantee a block.
        assert_eq!(block_attempts_cap(Some(3)), 5);
        // Unknown count: default to 10 (max PIV retry the spec allows) + margin.
        assert_eq!(block_attempts_cap(None), 12);
        // A pathological huge count is clamped so the loop can't run away.
        assert_eq!(block_attempts_cap(Some(200)), 22);
        // A raised PUK count (set-retries allows more than the old hardcoded 12)
        // still outlasts the card.
        assert_eq!(block_attempts_cap(Some(15)), 17);
    }

    #[test]
    fn credential_guess_is_eight_digits_and_varies() {
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        for _ in 0..64 {
            let guess = random_credential_guess(previous.as_ref().map(|g| g.as_slice())).unwrap();
            // 8 bytes keeps it inside the 6-8 range PIV and OpenPGP store, so
            // the card evaluates it instead of rejecting it on length.
            assert_eq!(guess.len(), 8);
            assert!(guess.iter().all(u8::is_ascii_digit));
            // Never the same twice running: an applet that ignores an unchanged
            // credential would not count the attempt.
            assert_ne!(previous.as_ref().map(|g| g.to_vec()), Some(guess.to_vec()));
            previous = Some(guess);
        }
    }

    #[test]
    fn credential_guess_steps_off_a_collision() {
        // Entropy that maps straight onto "01234567".
        let raw = [0u8, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(credential_guess_from(&raw, None).as_slice(), b"01234567");
        // Same draw, but that's what we just sent: last digit moves on.
        assert_eq!(
            credential_guess_from(&raw, Some(b"01234567")).as_slice(),
            b"01234568"
        );
        // The bump wraps rather than running past '9'.
        let nines = [9u8; 8];
        assert_eq!(
            credential_guess_from(&nines, Some(b"99999999")).as_slice(),
            b"99999990"
        );
    }

    #[test]
    fn reset_refusals_report_an_unrecoverable_card() {
        // The card's final word on RESET, once the PIN and PUK are already
        // blocked: 6983 (the one precondition RESET has, re-checked identically
        // on a re-run) and the 6D00 / 6A81 pair that means the instruction does
        // not exist. 6982 is NOT here — see reset_transient_refusals_fall_through.
        for e in [
            TransportError::PivResetNotAllowed,
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6D,
                sw2: 0x00,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6A,
                sw2: 0x81,
            },
        ] {
            let mapped = map_reset_stage_error(e);
            assert!(matches!(mapped, TransportError::PivResetIncomplete(_)));
            let text = mapped.to_string();
            // The message has to say what is true and never point back at the
            // command that just failed.
            assert!(text.contains("NOT wiped"));
            assert!(text.contains("no keyroost command"));
            assert!(!text.contains("re-run"));
        }
    }

    #[test]
    fn reset_transient_refusals_fall_through() {
        // Status words the card can answer under the RESET label that say
        // nothing about RESET being unavailable: 6F00 (no precise diagnosis),
        // 6881, and a 6A82 from an applet that momentarily lost its selection
        // after the blocking loops. The PIN and PUK really are blocked by then,
        // but the applet is still resettable — re-running the factory reset
        // against a quiescent applet succeeds — so calling the card
        // permanently unusable would steer the user away from the fix. These
        // pass through untouched and pick up the caller's re-run hint.
        //
        // 6982 (PivSecurityNotSatisfied) belongs here rather than with the
        // terminal set: RESET is not gated behind a security state, so a card
        // answering it is in an unexpected transient state, not declaring the
        // instruction impossible.
        for e in [
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6F,
                sw2: 0x00,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x68,
                sw2: 0x81,
            },
            TransportError::Apdu {
                label: "piv reset",
                sw1: 0x6A,
                sw2: 0x82,
            },
            TransportError::PivSecurityNotSatisfied,
        ] {
            let before = e.to_string();
            let mapped = map_reset_stage_error(e);
            assert!(!matches!(mapped, TransportError::PivResetIncomplete(_)));
            assert_eq!(mapped.to_string(), before);
        }
    }

    #[test]
    fn transport_faults_at_reset_are_left_alone() {
        // A card that stopped answering is not a card refusing RESET — the wipe
        // may still be finishable, so these must pass through unchanged.
        for e in [
            TransportError::ShortResponse {
                label: "piv",
                got: 1,
                expected_min: 2,
            },
            TransportError::MalformedResponse("applet continuation exceeded the chunk limit"),
            // A label from some other command can only mean an error that did
            // not originate at the RESET step.
            TransportError::Apdu {
                label: "piv pin/puk",
                sw1: 0x6A,
                sw2: 0x81,
            },
        ] {
            let before = e.to_string();
            assert_eq!(map_reset_stage_error(e).to_string(), before);
        }
    }
}

/// Issue #103: a T=0 contact card cannot receive extended-length APDUs and
/// may go silent when handed one, so the status-word fallback (#101) never
/// gets a status word to act on. On T=0 links, chaining must be the FIRST
/// choice, not the fallback.
#[cfg(test)]
mod chain_upfront_rule {
    use super::chain_upfront_for;

    #[test]
    fn t0_links_chain_from_the_start() {
        assert!(chain_upfront_for(true, false));
    }

    #[test]
    fn the_env_override_still_forces_chaining_on_any_link() {
        assert!(chain_upfront_for(false, true));
        assert!(chain_upfront_for(true, true));
    }

    #[test]
    fn t1_links_keep_extended_length_first() {
        // The #101 fallback covers a T=1 card that refuses extended length
        // with a status word; nothing here may pre-empt that path.
        assert!(!chain_upfront_for(false, false));
    }
}
