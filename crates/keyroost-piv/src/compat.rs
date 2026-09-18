//! Per-fingerprint known-support table for the non-standard PIV commands keyroost
//! exposes.
//!
//! A handful of management operations in this crate are vendor extensions, not
//! SP 800-73-4: Yubico's MOVE KEY and DELETE KEY, which landed in YubiKey
//! firmware 5.7. "Speaks PIV" says nothing about whether a given applet
//! implements them, and the answer can differ between firmware versions of the
//! same product. This module encodes what keyroost has actually observed,
//! keyed by [`AppletFingerprint`], as a **combined known-support table**: for each
//! fingerprint it knows about, a list of per-version verdicts each either
//! [`Verdict::KnownSupported`] ("extension known to be supported at this version")
//! or [`Verdict::KnownUnsupported`] ("extension known to be unsupported at this
//! version"). There are two such lists per extension — one keyed by the PIV
//! *applet's* own version, one by the *firmware's* — since the two can diverge
//! (see [`crate` root docs][crate] / `PivStatus::version` vs
//! `PivStatus::version_firmware` in `keyroost-transport`) and a fingerprint may
//! have data on one axis but not the other.
//!
//! [`resolve`] queries both tables with the live applet's fingerprint and its
//! applet and firmware versions and returns a three-way [`FeatureGate`] a UI
//! consumes directly: enable the control ([`FeatureGate::Supported`]), enable
//! it but flag it ([`FeatureGate::Unverified`]), or disable it
//! ([`FeatureGate::Unsupported`]). Each axis is queried independently with the
//! same semantics, then the two outcomes are combined (see [`resolve`] for the
//! combination rule). Per axis, a verdict extends across the untested
//! versions adjacent to it, in both directions: a known-supported verdict extends
//! *forward* ("known to work at this version, assumed to still work at any
//! later, untested version") and, symmetrically, a known-unsupported verdict extends
//! *backward* ("known not to work at this version, assumed not to work at any
//! earlier, untested version either"). Anything less certain — no verdicts
//! for the fingerprint at all, no reported version, or a known-unsupported verdict old
//! enough that a later firmware might have added the extension — resolves to
//! [`FeatureGate::Unverified`] on that axis, which keeps the control usable
//! unless the other axis disagrees.
//!
//! The same per-version rows also carry [`PivQuirk`]s — observed behavioral
//! wrinkles that need a workaround rather than gating a control. Quirks are
//! resolved separately by [`resolve_quirks`], with simpler semantics than
//! [`resolve`]: no known-support distinction, just "take the current entry on each
//! axis and merge whatever quirks it lists."
//!
//! [`PivExtension`] isn't limited to commands a UI puts a control in front
//! of, either: [`PivExtension::GetMetadata`] and [`PivExtension::Attest`]
//! are Yubico vendor extensions exactly like MOVE KEY/DELETE KEY, just
//! consumed internally (`keyroost-transport`'s `PivSession::metadata`/
//! `attest`) rather than gating a button — a fingerprint that has never
//! implemented one is a plain "unsupported extension" fact, the same shape
//! [`resolve`] already models, not a [`PivQuirk`] (which is reserved for a
//! device that *does* implement something and gets a detail of it wrong).

use std::collections::BTreeSet;

use crate::fingerprint::{
    AppletFingerprint, ArekinathVariant, HidCrescendoVariant, OpenFips201Variant, TrussedVariant,
    HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY,
};

/// One of the non-standard, vendor-extension PIV commands keyroost exposes —
/// nothing in SP 800-73-4 defines it, so support varies by applet and is
/// gated by device fingerprint through [`resolve`]. Not limited to commands a
/// UI puts a control in front of: [`Self::GetMetadata`]/[`Self::Attest`] are
/// consumed internally by `keyroost-transport`'s `PivSession`, gating
/// whether it bothers sending the APDU at all rather than gating a button.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivExtension {
    /// Yubico MOVE KEY — relocate a slot's private key into another slot.
    MoveKey,
    /// Yubico DELETE KEY — erase a slot's private key in place. Whether
    /// this is even worth *offering* on an already-empty slot is a
    /// separate question from whether the operation is supported at all —
    /// see [`Self::GetSlotKeyStatus`] for the gate a caller checks before
    /// trusting a "no key here" reading enough to block the button on it;
    /// this extension's own gate only answers "can DELETE KEY run here at
    /// all".
    DeleteKey,
    /// Yubico GET METADATA (`INS 0xF7`) — key/PIN algorithm, policy, origin,
    /// retries.
    GetMetadata,
    /// Whether a slot's private-key occupancy (does it hold a key at all,
    /// independent of any certificate) can be read straight from the
    /// device, rather than inferred. Unlike every other extension here,
    /// this one is **not** primarily version-gated per fingerprint —
    /// [`resolve`] special-cases it to fall through to
    /// [`Self::GetMetadata`]'s own verdict whenever `applet_verdicts` carries
    /// no [`Self::GetSlotKeyStatus`] entry for the fingerprint at all (see
    /// [`resolve`]'s doc for the mechanics), because GET METADATA's `algorithm` field *is*
    /// how this capability is provided on every fingerprint that provides
    /// it via a Yubico-compatible mechanism. An entry only belongs in a
    /// fingerprint's table when it reports slot key status through some
    /// *other*, independently-confirmed channel — today: HID Crescendo's
    /// GET PIV PROPERTIES
    /// (`keyroost_transport::PivSession::hid_crescendo_slot_algorithm`),
    /// which answers this even though [`Self::GetMetadata`] itself resolves
    /// [`FeatureGate::Unsupported`] there. Consumed internally, the same
    /// way [`Self::GetMetadata`]/[`Self::Attest`] are (see this enum's own
    /// doc) — `keyroost_transport::PivSession::slot_key_algorithm` already
    /// tries both channels unconditionally and doesn't need this gate to
    /// decide whether to bother; the one real consumer today is a UI
    /// deciding whether a `None` algorithm reading is trustworthy enough to
    /// *block* an operation on (see [`Self::DeleteKey`]'s doc for why that
    /// distinction matters there specifically).
    GetSlotKeyStatus,
    /// Yubico ATTEST (`INS 0xF9`) — a slot's self-signed attestation
    /// certificate, proving on-card key generation.
    Attest,
    /// Unlocking PIV management functionality (key-gen, cert import,
    /// set-retries, management-key rotation, …) via PIN VERIFY instead of the
    /// standard `0x9B` GENERAL AUTHENTICATE round. Some devices (HID
    /// Crescendo) implement this directly — PIN VERIFY alone satisfies the
    /// same access condition GENERAL AUTHENTICATE on `0x9B` would. Others
    /// (YubiKey) implement it only indirectly, via
    /// [`PivQuirk::PinManagementAuthProtected9BKey`]: PIN VERIFY unlocks
    /// *reading* the actual management key off a PIN-protected data object,
    /// and the standard `0x9B` round still has to run with that key
    /// afterward. Either way, a caller checks this extension first and then
    /// branches on whether the quirk is also set — see
    /// `keyroost_transport::PivSession::authenticate_management_via_pin`.
    PinManagementAuth,
    /// Resetting the PIV applet to factory defaults — wiping every slot's
    /// keys and certificates along with the PIN, PUK, and management key.
    /// SP 800-73-4 doesn't define one true mechanism for this: the dominant
    /// one in practice is Yubico's proprietary `INS 0xFB` "RESET" instruction
    /// (`keyroost_piv::piv::reset`), widely mimicked by other vendors, so
    /// keyroost defaults to sending it unless a fingerprint-specific rule
    /// selects a different sequence instead — see [`Self::ResetGlobal`] for
    /// HID Crescendo's own alternative
    /// (`keyroost_transport::PivSession::factory_reset` implements both,
    /// preferring `ResetGlobal`'s mechanism whenever it's available).
    /// Whether `INS
    /// 0xFB` is accepted can additionally depend on the quirk below, which
    /// this extension itself says nothing about — a caller checks support
    /// here first, then checks whether [`resolve_quirks`] reports
    /// [`PivQuirk::ResetNeedsManagementAuth`] (the HID Crescendo
    /// alternative); its absence carries a meaning of its own — see that
    /// quirk's doc. This extension is PIV-scoped only — see
    /// [`Self::ResetGlobal`] for the distinction from a reset that also takes
    /// other applets with it.
    Reset,
    /// A device-level reset directive that covers the PIV applet *and* at
    /// least one other applet in the same operation — HID Crescendo's own
    /// RESET CARD, run against its ACA (Access Control Applet) instance
    /// (`keyroost_piv::fingerprint::HID_CRESCENDO_ACA_AID`, `INS 0x38`;
    /// <https://docs.hidglobal.com/crescendo/api/c4000/reset-card.htm>),
    /// clears PIV's PKI keys and data containers alongside the XAUTH key,
    /// OATH keys/configuration, and (per the C4000 page) FIDO credentials —
    /// implemented by `keyroost_transport::PivSession::factory_reset`. This is
    /// what distinguishes it from [`Self::Reset`]:
    /// [`Self::Reset`] is defined as wiping *only* PIV, however it gets there;
    /// [`Self::ResetGlobal`] is a *different* directive, wider by definition,
    /// that happens to take PIV with it. It does not have to cover every
    /// applet on the device to count — PIV plus at least one other applet is
    /// enough — so a device offering this is not thereby claiming a full
    /// factory reset in one command, only that PIV isn't the only casualty.
    /// Resolved independently of [`Self::Reset`]: a device can support
    /// either, both, or neither.
    ResetGlobal,
    /// Setting the PIV PIN's and PUK's retry counters. The only mechanism
    /// keyroost implements today is Yubico SET PIN RETRIES (`INS 0xFA`,
    /// `keyroost_piv::set_pin_retries`) — one APDU that sets both counters
    /// together and resets both the PIN and the PUK to their factory
    /// defaults in the process, with no way to change one counter without
    /// the other, so unlike [`Self::MoveKey`]/[`Self::DeleteKey`] (two
    /// genuinely independent operations that just happen to share a YubiKey
    /// known-support row) this is modeled as a single extension covering
    /// both counters, not two separate PIN/PUK gates. This extension names
    /// the *capability*, though, not that one specific wire mechanism: a
    /// vendor can reach the same result its own proprietary way — HID
    /// Crescendo's SDK exposes an `UpdatePINProperties` method that in
    /// principle covers this ground (see [`HID_CRESCENDO_C4000_APPLET_VERDICTS`]'s
    /// doc) — the same shape [`Self::PinManagementAuth`] already
    /// uses for a capability two vendors reach by genuinely different
    /// mechanisms (direct PIN unlock on HID Crescendo, the indirect
    /// PIN-protected-management-key scheme on YubiKey) under one gate. A
    /// fingerprint with a confirmed alternative mechanism would resolve
    /// [`FeatureGate::Supported`] here too, once keyroost has an APDU-level
    /// implementation of it to run. Until then, every non-YubiKey verdict on
    /// this extension reflects keyroost only having the Yubico extension
    /// implemented and probed for — not a claim that no other device could
    /// ever support the capability.
    SetPinPukRetries,
}

impl PivExtension {
    /// A one-sentence statement of what running this extension needs, phrased
    /// for the user. A UI or the CLI follows it with a state-specific suffix —
    /// [`FeatureGate::UNVERIFIED_SUFFIX`] or [`FeatureGate::INCOMPATIBLE_SUFFIX`]
    /// — so both surfaces say the same thing.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            PivExtension::MoveKey => {
                "Moving keys between slots needs YubiKey 5.7+ or a compatible third-party device."
            }
            PivExtension::DeleteKey => {
                "Key deletion needs YubiKey 5.7+ or a compatible third-party device."
            }
            PivExtension::GetMetadata => {
                "Reading key/PIN metadata needs YubiKey firmware 5.3+ or a compatible \
                 third-party device."
            }
            PivExtension::GetSlotKeyStatus => {
                "Reading a slot's key occupancy directly needs YubiKey firmware 5.3+ or a \
                 compatible third-party device."
            }
            PivExtension::Attest => {
                "Reading a key's attestation certificate needs YubiKey firmware 4.3+ or a \
                 compatible third-party device."
            }
            PivExtension::PinManagementAuth => {
                "Unlocking management with a PIN instead of the management key needs \
                 YubiKey 3+ or a compatible third-party device."
            }
            PivExtension::Reset => {
                "Resetting the PIV applet needs a YubiKey or a compatible third-party device."
            }
            PivExtension::ResetGlobal => {
                "A device-wide reset that takes PIV with it needs a compatible third-party \
                 device (e.g. HID Crescendo)."
            }
            PivExtension::SetPinPukRetries => {
                "Setting the PIN/PUK retry counts needs a YubiKey or a compatible third-party \
                 device."
            }
        }
    }
}

/// A version-gated behavioral wrinkle keyroost has observed on some PIV
/// devices — distinct from [`PivExtension`]: an extension is "supported or
/// not", a quirk is "present and needs a workaround" regardless of support.
/// Carried on [`VersionQuirks::quirks`] and surfaced by [`resolve_quirks`].
/// Nothing in this crate acts on a resolved quirk yet — the workaround code
/// for each one lands separately.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PivQuirk {
    /// The serial number returned by the Yubico extension APDU GET SERIAL
    /// (`INS 0xF8`) is packed BCD encoded rather than a plain big-endian
    /// integer.
    InsF8SerialIsBcd,
    /// The algorithm identifier (tag `0x01`) in the Yubico extension APDU GET
    /// METADATA (`INS 0xF7`) response never updates on this device — it does
    /// not reflect the slot's actual key state — and must always be ignored
    /// when this quirk is set, regardless of what value is read.
    InsF7MetadataAlgorithmInvalid,
    /// [`PivExtension::PinManagementAuth`] is available on this device, but
    /// PIN VERIFY doesn't unlock management functionality by itself — it only
    /// unlocks *reading* the real management key, which the card stores PIN-
    /// protected in a data object (tag `0x88`, subtag `0x89`, inside PIV data
    /// object `5F C1 09` on YubiKey — see
    /// `keyroost_piv::parse_pin_protected_management_key`). A caller that
    /// wants PIN-based management unlock on a device with this quirk set
    /// still has to read that key back and run the standard `0x9B` GENERAL
    /// AUTHENTICATE round with it — see
    /// `keyroost_transport::PivSession::authenticate_management_via_pin`. If
    /// the read comes back with no tag 88 / subtag 89, PIN management auth
    /// simply hasn't been set up on this card yet.
    PinManagementAuthProtected9BKey,
    /// [`PivExtension::Reset`] and [`PivExtension::ResetGlobal`] require
    /// an authenticated management-key session before it is accepted —
    /// e.g. HID Crescendo's own reset mechanism
    /// (<https://docs.hidglobal.com/crescendo/api/low-level/reset-card.htm>),
    /// implemented by `keyroost_transport::PivSession::factory_reset`.
    ///
    /// A fingerprint that does *not* carry this quirk only means RESET
    /// doesn't need an authenticated management-key session — it is *not* a
    /// promise that PIN/PUK blocking is required instead. The widespread
    /// YubiKey convention layers that precondition on top (`INS 0xFB`
    /// accepted with no management-key session at all, but only once the PIV
    /// PIN *and* PUK are both already blocked — every retry exhausted), and
    /// for a long time that was the only alternative keyroost had observed to
    /// this quirk's mechanism, but it isn't the only one: a live Token2
    /// applet at version 5.112.0 has been observed accepting `INS 0xFB`
    /// outright, with neither the PIN nor the PUK blocked and no
    /// authenticated session either (see [`TOKEN2_APPLET_VERDICTS`]'s
    /// doc) — so this quirk's absence really only
    /// answers "does RESET need management auth", not "what, if anything,
    /// RESET needs instead".
    ///
    /// `keyroost_transport::PivSession::force_reset` is written for exactly
    /// this uncertainty: it always tries a bare RESET first and only starts
    /// burning PIN/PUK retries if that bare attempt comes back
    /// `PivResetNotAllowed` (the YubiKey-style "blocked precondition" status
    /// words). On a device that accepts RESET unconditionally, like the
    /// Token2 unit above, the bare attempt already succeeds and nothing ever
    /// gets burned; on a device that actually enforces the blocked-PIN/PUK
    /// precondition, the bare attempt's refusal is what triggers the burn.
    /// Neither this quirk nor [`PivExtension::Reset`]'s verdict distinguishes
    /// the two cases up front — `force_reset` finds out empirically instead
    /// of assuming either one.
    ///
    /// **Safety constraint on that burn:** deliberately burning through PIN
    /// and PUK retries to unlock RESET must only ever run when
    /// [`PivExtension::Reset`] resolves [`FeatureGate::Supported`] — never
    /// [`FeatureGate::Unverified`]. A blocked-precondition refusal is only
    /// good evidence a burn will help when RESET is confirmed to exist on
    /// this device; doing it on a device where RESET support is merely
    /// unverified risks bricking it outright if `INS 0xFB` then turns out
    /// unsupported there — PIN and PUK both blocked with no working RESET is
    /// unrecoverable. [`FeatureGate::Unverified`] must fall back to a manual,
    /// user-driven PIN/PUK block (or simply refuse), same as any other
    /// unverified extension. `keyroost_transport::PivSession::plan_factory_reset`
    /// enforces this by resolving `FactoryResetPlan::Unverified` rather than
    /// `FactoryResetPlan::BurnPinPukThenReset` whenever the gate isn't
    /// [`FeatureGate::Supported`].
    ResetNeedsManagementAuth,
    /// This fingerprint (at the version the entry covers) ships with a
    /// well-known, publicly documented factory-default value for the
    /// standard PIV management key (key reference `0x9B`) — the raw key
    /// bytes are carried right on the variant, unlike every other
    /// [`PivQuirk`], because there's nothing else to derive them from.
    /// Deliberately a slice, not a fixed-size array: `0x9B`'s algorithm
    /// varies by fingerprint (and, on YubiKey, by firmware — 3-DES/AES-192
    /// are 24 bytes, but AES-128 is 16 and AES-256 is 32; see
    /// [`crate::MgmtAlg::key_len`]), so a caller must not assume any one
    /// length for this quirk's payload. A caller offering a "use the default
    /// management key" convenience reads this off [`resolve_quirks`] (via
    /// [`default_9b_management_key`]) and disables that convenience entirely
    /// when it's absent — an absent entry means keyroost has no known
    /// default for this fingerprint, not that the device has none; see each
    /// fingerprint's own applet-axis quirks const (e.g. [`YUBIKEY_APPLET_QUIRKS`])
    /// for what's actually known.
    ///
    /// Four distinct values are seeded today, each shared by every
    /// fingerprint observed to ship it:
    /// * `01 02 03 04 05 06 07 08` repeated three times (24 bytes) — the
    ///   standard PIV default YubiKey documents
    ///   (<https://docs.yubico.com/software/yubikey/tools/authenticator/auth-guide/piv-certificates.html>)
    ///   and a wide range of third-party PIV implementations mimic outright,
    ///   not just genuine YubiKeys — including the Trussed `piv-authenticator`
    ///   (fingerprinted as [`AppletFingerprint::Trussed`]), whose
    ///   `constants.rs` hard-codes this exact value as
    ///   `DEFAULT_MANAGEMENT_KEY`
    ///   (<https://github.com/trussed-dev/piv-authenticator/blob/main/src/constants.rs>).
    /// * Token2's own vendor-specific value (24 bytes)
    ///   (<https://www.token2.com/pages/pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases>).
    /// * Feitian's own vendor-specific value (24 bytes)
    ///   (<https://fido.ftsafe.com/feitian-sk-manager-tool-user-manual/>).
    /// * HID Crescendo's documented all-zero factory-delivery value for XAUTH
    ///   key 1 (24 bytes, [`HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY`]) — HID
    ///   Crescendo has no standard PIV management key at all (see
    ///   [`PivExtension::PinManagementAuth`]'s doc), but the same "well-known
    ///   default credential" convenience applies to its XAUTH key, so it's
    ///   seeded here too rather than duplicated through a parallel
    ///   mechanism; `keyroost_transport::PivSession`'s HID Crescendo reset
    ///   path reads this entry back to restore XAUTH key 1 after RESET CARD,
    ///   rather than hard-coding the constant a second time.
    ///
    /// Every seeded value today happens to be 24 bytes, but that's a fact
    /// about what's been observed so far, not a constraint this variant
    /// enforces — a future row for an AES-128 or AES-256 default must not
    /// need this type to change.
    Default9bManagementKey(&'static [u8]),
    /// This fingerprint (at the version the entry covers) is known to take
    /// unusually long to complete [`PivExtension::Reset`] — observed at over
    /// a minute on `ArekinathPivApplet::SwissbitIShield1`
    /// (<https://github.com/swissbit-eis/PivApplet>). Says nothing about
    /// whether RESET is *supported* — that's still
    /// [`PivExtension::Reset`]'s own [`resolve`] verdict, queried
    /// separately — only that, when it is, a caller shouldn't mistake a slow
    /// device for a hung one. A caller that finds this quirk set (via
    /// [`resolve_quirks`]) should surface [`Self::RESET_LONG_RUNNING_HINT`]
    /// to the user before running RESET, worded identically wherever it's
    /// shown so the GUI and the CLI say the same thing.
    ResetLongRunning,
}

impl PivQuirk {
    /// Shared wording for [`Self::ResetLongRunning`], reused verbatim by the
    /// GUI's PIV pane (Reset applet card) and `keyroostctl piv reset` so
    /// both surfaces warn in the same words rather than drifting apart.
    pub const RESET_LONG_RUNNING_HINT: &'static str = "This device is known to take a long \
        time to reset \u{2014} more than a minute is not unusual. Be patient; do not unplug \
        the device or abort.";
}

/// Extract the well-known factory-default management-key bytes from a
/// resolved quirk set, if [`PivQuirk::Default9bManagementKey`] is present in
/// it — [`resolve_quirks`]'s return value is the expected input. `None` means
/// keyroost has no known default for this fingerprint/version, the signal a
/// "use the default management key" UI convenience uses to disable itself.
/// The returned slice's length is whatever that fingerprint's management-key
/// algorithm actually takes (16/24/32 bytes) — never assume 24.
#[must_use]
pub fn default_9b_management_key(quirks: &BTreeSet<PivQuirk>) -> Option<&'static [u8]> {
    quirks.iter().find_map(|q| match q {
        PivQuirk::Default9bManagementKey(key) => Some(*key),
        _ => None,
    })
}

/// One extension's known-support verdicts within one fingerprint's
/// applet-axis or firmware-axis table — e.g. [`YUBIKEY_APPLET_VERDICTS`].
struct ExtensionVerdicts {
    extension: PivExtension,
    /// This (fingerprint, extension) pair's per-version verdicts, **ascending
    /// by [`VersionVerdict::version`]** and non-empty.
    verdicts: &'static [VersionVerdict],
}

/// "At [`Self::version`] (and, until the next one, above it) the extension's
/// verdict is [`Self::verdict`]." Versions are compared as plain byte slices,
/// the same ordering `keyroost_transport::PivStatus::version` uses elsewhere
/// (`[] < [5, 7] < [5, 7, 0] < [5, 8]`).
struct VersionVerdict {
    version: &'static [u8],
    verdict: Verdict,
}

/// One recorded known-support verdict, carried by a [`VersionVerdict`].
// The shared `Known` prefix is deliberate, not accidental redundancy: it
// groups these three as one family at a glance (in a match arm, in
// autocomplete, in this enum's own listing) — see each variant's doc for how
// they differ.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Extension known to be supported at this version (and, by the
    /// no-regression assumption in [`resolve`], at every later one until a
    /// contrary verdict). Says nothing about versions *before* it.
    KnownSupported,
    /// Extension known to be unsupported at this version, and — in the
    /// absence of a later verdict on the same row — assumed to have been
    /// unsupported at every earlier, untested version too (the backward
    /// mirror of [`Self::KnownSupported`]'s forward, no-regression
    /// assumption). Unlike [`Self::KnownUnsupportedSince`], this one
    /// *doesn't* extend forward past itself: a version newer than every
    /// verdict on the row softens to [`FeatureGate::Unverified`], since a
    /// later firmware may simply have added the extension.
    KnownUnsupported,
    /// Extension known to be unsupported at this version, and — the mirror
    /// image of [`Self::KnownSupported`]'s extension direction rather than
    /// [`Self::KnownUnsupported`]'s — assumed to *stay* unsupported at every
    /// later, untested version too, with no softening to
    /// [`FeatureGate::Unverified`] the way [`Self::KnownUnsupported`] gets.
    /// Says nothing about versions *before* it: an earlier version might
    /// have supported the extension, e.g. a vendor SDK generation that
    /// implemented it before a later architectural pivot away from it.
    ///
    /// For a case where merely "no verdict this old has flipped yet" isn't
    /// the reasoning — where there's a specific, standing reason to expect
    /// the vendor never will: a vendor with a track record of never
    /// mimicking Yubico's extension APDUs, instead consistently building its
    /// own proprietary alternatives, is unlikely to start mimicking Yubico
    /// now. That's a bet about the vendor's whole pattern of behavior, not
    /// just an absence observed on one firmware, so use this instead of
    /// [`Self::KnownUnsupported`] for it — see e.g. HID Crescendo's
    /// [`PivExtension::GetMetadata`]/[`PivExtension::Attest`] rows in
    /// [`HID_CRESCENDO_C2300_APPLET_VERDICTS`], which apply this reasoning
    /// to a vendor that has never implemented *any* Yubico extension APDU
    /// and instead ships its own (ACA XAUTH in place of `GENERAL
    /// AUTHENTICATE` on `0x9B`, GET PIV PROPERTIES in place of GET
    /// METADATA). Use [`Self::KnownUnsupported`] instead for an ordinary "no
    /// evidence either way yet" gap.
    KnownUnsupportedSince,
}

/// "At [`Self::version`] (and, until a later entry, above it) these quirks
/// are active." Same version-ordering convention as [`VersionVerdict`], but
/// purely additive: there's no known-supported/known-unsupported state, so a quirk
/// entry can never suppress a quirk an earlier entry already reported.
struct VersionQuirks {
    version: &'static [u8],
    quirks: &'static [PivQuirk],
}

/// The commonly-mimicked YubiKey PIV factory-default management key: 24
/// bytes of `01 02 03 04 05 06 07 08` repeated three times (3-DES /
/// AES-192) —
/// <https://docs.yubico.com/software/yubikey/tools/authenticator/auth-guide/piv-certificates.html>.
/// Seeded on [`PivQuirk::Default9bManagementKey`] for every fingerprint known
/// to ship this exact value, genuine YubiKeys and third-party mimics alike —
/// see that variant's doc.
const YUBIKEY_DEFAULT_MGMT_KEY: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// Token2's own vendor-specific PIV factory-default management key —
/// <https://www.token2.com/pages/pin-firmware-feature-support-matrix-openpgp-fido2-otp-and-piv-across-releases>.
const TOKEN2_DEFAULT_MGMT_KEY: &[u8] = &[
    0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62, 0x86,
    0x53, 0x62, 0x86, 0x53, 0x62, 0x86, 0x53, 0x62,
];

/// Feitian's own vendor-specific PIV factory-default management key — ASCII
/// `"12345678"` repeated three times —
/// <https://fido.ftsafe.com/feitian-sk-manager-tool-user-manual/>.
const FEITIAN_DEFAULT_MGMT_KEY: &[u8] = &[
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
];

/// This fingerprint's known-support verdicts for `extension`, keyed by the
/// PIV **applet's own** version (Yubico's `GET VERSION` extension reply, or —
/// for HID Crescendo — the version its own GET PIV PROPERTIES query reports).
/// Dispatches to one const table per fingerprint (see each table's own doc
/// for its data and reasoning) and looks `extension` up within it. `None`
/// means keyroost has no applet-version data for this (fingerprint,
/// extension) pair — either the fingerprint has no table at all, or its
/// table has no entry for `extension` — and [`resolve`] treats that axis as
/// [`FeatureGate::Unverified`] for it.
#[must_use]
fn applet_verdicts(
    fingerprint: AppletFingerprint,
    extension: PivExtension,
) -> Option<&'static [VersionVerdict]> {
    find_verdicts(
        match fingerprint {
            AppletFingerprint::YubiKey => YUBIKEY_APPLET_VERDICTS,
            AppletFingerprint::Token2 => TOKEN2_APPLET_VERDICTS,
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
                SWISSBIT_ISHIELD2_APPLET_VERDICTS
            }
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
                OPENFIPS201_GENERIC_APPLET_VERDICTS
            }
            AppletFingerprint::Thetis => THETIS_APPLET_VERDICTS,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
                AREKINATH_GENERIC_APPLET_VERDICTS
            }
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
                AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
                HID_CRESCENDO_C2300_APPLET_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
                HID_CRESCENDO_C4000_APPLET_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
                HID_CRESCENDO_GENERIC_APPLET_VERDICTS
            }
            AppletFingerprint::Generic => GENERIC_APPLET_VERDICTS,
            AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_APPLET_VERDICTS,
            AppletFingerprint::Feitian => FEITIAN_APPLET_VERDICTS,
            AppletFingerprint::IdPrime => IDPRIME_APPLET_VERDICTS,
            AppletFingerprint::Trussed(TrussedVariant::NitroKey) => {
                TRUSSED_NITROKEY_APPLET_VERDICTS
            }
            AppletFingerprint::UTrust => UTRUST_APPLET_VERDICTS,
        },
        extension,
    )
}

/// Same lookup as [`applet_verdicts`], against each fingerprint's
/// **firmware**-version table instead — e.g. [`YUBIKEY_FIRMWARE_VERDICTS`].
/// Every one of those tables is empty today: no fingerprint has
/// firmware-version data for any extension yet (HID Crescendo's GET PIV
/// PROPERTIES version is an *applet* version, not a firmware one — see
/// [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]'s doc).
#[must_use]
fn firmware_verdicts(
    fingerprint: AppletFingerprint,
    extension: PivExtension,
) -> Option<&'static [VersionVerdict]> {
    find_verdicts(
        match fingerprint {
            AppletFingerprint::YubiKey => YUBIKEY_FIRMWARE_VERDICTS,
            AppletFingerprint::Token2 => TOKEN2_FIRMWARE_VERDICTS,
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
                SWISSBIT_ISHIELD2_FIRMWARE_VERDICTS
            }
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
                OPENFIPS201_GENERIC_FIRMWARE_VERDICTS
            }
            AppletFingerprint::Thetis => THETIS_FIRMWARE_VERDICTS,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
                AREKINATH_GENERIC_FIRMWARE_VERDICTS
            }
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
                AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
                HID_CRESCENDO_C2300_FIRMWARE_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
                HID_CRESCENDO_C4000_FIRMWARE_VERDICTS
            }
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
                HID_CRESCENDO_GENERIC_FIRMWARE_VERDICTS
            }
            AppletFingerprint::Generic => GENERIC_FIRMWARE_VERDICTS,
            AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_FIRMWARE_VERDICTS,
            AppletFingerprint::Feitian => FEITIAN_FIRMWARE_VERDICTS,
            AppletFingerprint::IdPrime => IDPRIME_FIRMWARE_VERDICTS,
            AppletFingerprint::Trussed(TrussedVariant::NitroKey) => {
                TRUSSED_NITROKEY_FIRMWARE_VERDICTS
            }
            AppletFingerprint::UTrust => UTRUST_FIRMWARE_VERDICTS,
        },
        extension,
    )
}

/// Shared lookup backing [`applet_verdicts`]/[`firmware_verdicts`]: find
/// `extension`'s entry within one fingerprint's already-selected table.
#[must_use]
fn find_verdicts(
    table: &'static [ExtensionVerdicts],
    extension: PivExtension,
) -> Option<&'static [VersionVerdict]> {
    table
        .iter()
        .find(|e| e.extension == extension)
        .map(|e| e.verdicts)
}

/// This fingerprint's active [`PivQuirk`]s, keyed by the PIV **applet's own**
/// version. Dispatches to one const per fingerprint (see each const's own
/// doc for its data and reasoning) and returns it outright — unlike
/// [`applet_verdicts`]/[`firmware_verdicts`], there's no extension axis to
/// look up within it, since a quirk applies to the fingerprint/version as a
/// whole (see [`PivQuirk`]'s own doc). A fingerprint with no data at all
/// (today: [`AppletFingerprint::IdPrime`] and
/// `AppletFingerprint::OpenFips201(`[`OpenFips201Variant::Generic`]`)`)
/// still gets its own const — [`IDPRIME_APPLET_QUIRKS`]/
/// [`OPENFIPS201_GENERIC_APPLET_QUIRKS`] — just an empty one, the same as an
/// unpopulated firmware-axis const.
#[must_use]
fn applet_quirks(fingerprint: AppletFingerprint) -> &'static [VersionQuirks] {
    match fingerprint {
        AppletFingerprint::YubiKey => YUBIKEY_APPLET_QUIRKS,
        AppletFingerprint::Token2 => TOKEN2_APPLET_QUIRKS,
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
            SWISSBIT_ISHIELD2_APPLET_QUIRKS
        }
        AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
            OPENFIPS201_GENERIC_APPLET_QUIRKS
        }
        AppletFingerprint::Thetis => THETIS_APPLET_QUIRKS,
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
            AREKINATH_GENERIC_APPLET_QUIRKS
        }
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
            AREKINATH_SWISSBIT_ISHIELD1_APPLET_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
            HID_CRESCENDO_C2300_APPLET_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
            HID_CRESCENDO_C4000_APPLET_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
            HID_CRESCENDO_GENERIC_APPLET_QUIRKS
        }
        AppletFingerprint::Generic => GENERIC_APPLET_QUIRKS,
        AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_APPLET_QUIRKS,
        AppletFingerprint::Feitian => FEITIAN_APPLET_QUIRKS,
        AppletFingerprint::IdPrime => IDPRIME_APPLET_QUIRKS,
        AppletFingerprint::Trussed(TrussedVariant::NitroKey) => TRUSSED_NITROKEY_APPLET_QUIRKS,
        AppletFingerprint::UTrust => UTRUST_APPLET_QUIRKS,
    }
}

/// Same lookup as [`applet_quirks`], against each fingerprint's **firmware**
/// axis instead — e.g. [`YUBIKEY_FIRMWARE_QUIRKS`]. Every one of those
/// consts is empty today: no fingerprint has firmware-version-gated quirk
/// data yet.
#[must_use]
fn firmware_quirks(fingerprint: AppletFingerprint) -> &'static [VersionQuirks] {
    match fingerprint {
        AppletFingerprint::YubiKey => YUBIKEY_FIRMWARE_QUIRKS,
        AppletFingerprint::Token2 => TOKEN2_FIRMWARE_QUIRKS,
        AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2) => {
            SWISSBIT_ISHIELD2_FIRMWARE_QUIRKS
        }
        AppletFingerprint::OpenFips201(OpenFips201Variant::Generic) => {
            OPENFIPS201_GENERIC_FIRMWARE_QUIRKS
        }
        AppletFingerprint::Thetis => THETIS_FIRMWARE_QUIRKS,
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic) => {
            AREKINATH_GENERIC_FIRMWARE_QUIRKS
        }
        AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1) => {
            AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300) => {
            HID_CRESCENDO_C2300_FIRMWARE_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000) => {
            HID_CRESCENDO_C4000_FIRMWARE_QUIRKS
        }
        AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic) => {
            HID_CRESCENDO_GENERIC_FIRMWARE_QUIRKS
        }
        AppletFingerprint::Generic => GENERIC_FIRMWARE_QUIRKS,
        AppletFingerprint::AuthentrendATKey => AUTHENTREND_ATKEY_FIRMWARE_QUIRKS,
        AppletFingerprint::Feitian => FEITIAN_FIRMWARE_QUIRKS,
        AppletFingerprint::IdPrime => IDPRIME_FIRMWARE_QUIRKS,
        AppletFingerprint::Trussed(TrussedVariant::NitroKey) => TRUSSED_NITROKEY_FIRMWARE_QUIRKS,
        AppletFingerprint::UTrust => UTRUST_FIRMWARE_QUIRKS,
    }
}

// --- Per-device tables ---------------------------------------------------
//
// Four consts per fingerprint below, always in the same order — applet-axis
// known-support verdicts, firmware-axis known-support verdicts, applet-axis
// quirks, then firmware-axis quirks — so a device's complete data set sits
// together as one block, rather than being split across separate
// axis-at-a-time or verdicts/quirks-at-a-time tables. Looked up through
// `applet_verdicts`/`firmware_verdicts` (verdicts) and
// `applet_quirks`/`firmware_quirks` (quirks) — see each function's own doc
// for its axis' lookup semantics.
//
// Every firmware-axis const is empty today: no fingerprint has
// firmware-version data for any extension or quirk yet (HID Crescendo's GET
// PIV PROPERTIES version is an *applet* version — see
// `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc — not a firmware one).
//
// `PivQuirk::Default9bManagementKey` entries deliberately repeat the quirk
// on every `VersionQuirks` entry of a quirks const that has more than one:
// per `latest_quirks`, entries don't accumulate with each other, only across
// the applet/firmware axes, so a version-gated const that only listed the
// default key on its earliest entry would lose it again once a later entry
// (e.g. one clearing an unrelated, actually version-gated quirk) takes over.
// The default management key itself is not known to be version-gated for
// any seeded fingerprint, so it's simply carried on every entry of a const
// instead of modeling a fourth axis for it.

/// YubiKey's applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`] — shipped
///   together in firmware 5.7: unsupported at every earlier version,
///   supported from 5.7 on. The empty-slice version on the known-unsupported
///   verdict is a "from the very first version" sentinel — it orders below
///   every real version (`[] < [5, 7]`), so that verdict is the one that
///   applies to anything older than 5.7. This sentinel is load-bearing and
///   not implied by [`resolve_in`]'s backward-extension rule: the verdict
///   *above* it is a known-supported verdict (`[5, 7]`), not
///   known-unsupported, and a known-supported verdict says nothing about
///   versions before it.
/// * [`PivExtension::Attest`] — shipped in firmware 4.3
///   (<https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>:
///   "Only available in YubiKey 4.3 & 5"): same shape as MOVE KEY/DELETE KEY
///   above — a known-unsupported verdict at the `[]` sentinel and a
///   known-supported verdict at `[4, 3]`.
/// * [`PivExtension::GetMetadata`] — shipped in firmware 5.3 (same reference:
///   "Only available in YubiKey 5.3"), same shape again with the
///   known-supported verdict at `[5, 3]` instead.
/// * [`PivExtension::PinManagementAuth`] — [`Verdict::KnownSupported`] from
///   applet version 3 on. This is the *indirect* scheme:
///   [`PivQuirk::PinManagementAuthProtected9BKey`] is set on
///   [`YUBIKEY_APPLET_QUIRKS`], so a caller still has to read the
///   PIN-protected management key back and run the standard `0x9B` round
///   with it — see [`PivExtension::PinManagementAuth`]'s own doc.
/// * [`PivExtension::Reset`] — RESET (`INS 0xFB`) has been supported by
///   every YubiKey PIV implementation observed, so this is a single
///   [`Verdict::KnownSupported`] at the universal `[]` version, no
///   known-unsupported floor to gate below it — unlike MOVE KEY/DELETE KEY
///   above, RESET didn't arrive in a specific later firmware. YubiKey
///   carries no [`PivQuirk::ResetNeedsManagementAuth`] entry on
///   [`YUBIKEY_APPLET_QUIRKS`] either: "supported" here means
///   the card accepts the instruction, not that it accepts it
///   unconditionally — the precondition (PIN *and* PUK both already
///   blocked) is exactly what that quirk's absence signals, per its own doc.
/// * [`PivExtension::SetPinPukRetries`] — supported by every YubiKey PIV
///   implementation
///   (<https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#set-pin-retries>:
///   "All YubiKeys with the PIV application."), same shape as
///   [`PivExtension::Reset`] above: a single [`Verdict::KnownSupported`] at
///   the universal `[]` version, no known-unsupported floor — unlike MOVE
///   KEY/DELETE KEY's row, this didn't arrive in a specific later firmware.
/// * [`PivExtension::ResetGlobal`] — [`Verdict::KnownUnsupportedSince`] at
///   the universal `[]` version, same as every other non-HID-Crescendo
///   fingerprint's table — see e.g. [`GENERIC_APPLET_VERDICTS`]'s doc for why.
/// * No entry for [`PivExtension::GetSlotKeyStatus`] — falls through to
///   [`PivExtension::GetMetadata`]'s own verdict above, per [`resolve`]'s
///   special case.
const YUBIKEY_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 7],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 7],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::Attest,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[4, 3],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetMetadata,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 3],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::PinManagementAuth,
        verdicts: &[VersionVerdict {
            version: &[3],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::Reset,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::SetPinPukRetries,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// YubiKey's firmware-axis known-support verdicts — empty: no fingerprint
/// has firmware-version data for any extension yet (HID Crescendo's GET PIV
/// PROPERTIES version is an *applet* version — see
/// [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]'s doc — not a firmware one). Every
/// other `_FIRMWARE_VERDICTS` const below is empty for the same reason.
const YUBIKEY_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// YubiKey's applet-axis quirks. Matches [`YUBIKEY_APPLET_VERDICTS`]'s
/// PinManagementAuth row: applet version 3 is where
/// [`PivExtension::PinManagementAuth`] becomes known-supported, and on
/// YubiKey it's always the indirect PIN-protected-management-key scheme,
/// never a direct PIN unlock — see [`PivQuirk::PinManagementAuthProtected9BKey`]'s
/// own doc. YubiKey carries no [`PivQuirk::ResetNeedsManagementAuth`] entry
/// at all — its absence is exactly how a caller learns RESET follows the
/// PIN/PUK-blocked convention instead; see that quirk's doc. The
/// default-management-key quirk isn't gated on that same version split —
/// it's repeated on both entries so it applies below applet version 3 too.
const YUBIKEY_APPLET_QUIRKS: &[VersionQuirks] = &[
    VersionQuirks {
        version: &[],
        quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
    },
    VersionQuirks {
        version: &[3],
        quirks: &[
            PivQuirk::PinManagementAuthProtected9BKey,
            PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
        ],
    },
];

/// YubiKey's firmware-axis quirks — empty: no fingerprint has
/// firmware-version-gated quirk data yet. Every other `_FIRMWARE_QUIRKS`
/// const below is empty for the same reason.
const YUBIKEY_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Token2's applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`] — applet version
///   5.112.0 has been observed to reject both outright, and every version
///   below it is assumed to as well per [`resolve_in`]'s backward-extension
///   rule (no earlier hardware has been available to test, but a feature
///   known not to work at 5.112.0 is presumed not to work in any older,
///   untested version either). There is no known-supported verdict on either
///   row, so a version *above* 5.112.0 resolves [`FeatureGate::Unverified`],
///   not [`FeatureGate::Unsupported`] — a known-unsupported verdict is
///   deliberately never treated as covering a version it hasn't actually
///   observed on the other side either. Neither row needs an explicit `[]`
///   sentinel: the single `[5, 112, 0]` known-unsupported verdict is enough
///   for [`resolve_in`] to extend backward on its own.
/// * [`PivExtension::Reset`] — [`Verdict::KnownSupported`] pinned to applet
///   version 5.112.0, the only version keyroost has hardware evidence for: a
///   live unit at this version accepts `INS 0xFB`. Token2 carries no
///   [`PivQuirk::ResetNeedsManagementAuth`] entry on [`TOKEN2_APPLET_QUIRKS`]
///   either, so — same as YubiKey — this device doesn't need an
///   authenticated management-key session for RESET. Unlike YubiKey, though,
///   that same live unit accepted `INS 0xFB` with *neither* the PIN nor the
///   PUK blocked — it does not also fall back to the YubiKey convention's
///   blocked-precondition gate; see
///   [`PivQuirk::ResetNeedsManagementAuth`]'s own doc for why this quirk's
///   absence doesn't imply that convention. No known-unsupported floor is
///   recorded below 5.112.0, so an older reported version resolves
///   [`FeatureGate::Unverified`] rather than inheriting this verdict
///   backward — unlike YubiKey's universal `[]` version, this one only
///   speaks for 5.112.0 and later.
/// * [`PivExtension::SetPinPukRetries`] — [`Verdict::KnownSupported`] pinned
///   to applet version 5.112.0, the only version keyroost has hardware
///   evidence for: a live unit at this version accepts Yubico's SET PIN
///   RETRIES APDU. Unlike the MOVE KEY/DELETE KEY rows above — both
///   [`Verdict::KnownUnsupported`] at this same version — Token2 mimics some
///   Yubico extension APDUs and not others, so each extension's verdict for
///   this fingerprint is independent and this row's positive result doesn't
///   imply anything about those two. No known-unsupported floor is recorded
///   below 5.112.0 here either.
/// * [`PivExtension::ResetGlobal`] — [`Verdict::KnownUnsupportedSince`] at
///   the universal `[]` version — see [`GENERIC_APPLET_VERDICTS`]'s doc for
///   why.
/// * [`PivExtension::GetMetadata`] — [`Verdict::KnownSupported`] pinned to
///   applet version 5.112.0, same single-verdict shape as
///   [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`] above: a live
///   unit at this version answers GET METADATA. No known-unsupported floor is
///   recorded below 5.112.0 here either, so an older reported version
///   resolves [`FeatureGate::Unverified`] rather than inheriting this verdict
///   backward.
/// * No entries for [`PivExtension::Attest`] or
///   [`PivExtension::PinManagementAuth`].
const TOKEN2_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::Reset,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::SetPinPukRetries,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetMetadata,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const TOKEN2_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Token2's applet-axis quirks: GET SERIAL's reply is packed BCD rather than
/// a plain big-endian integer, and this fingerprint ships its own
/// vendor-specific default management key ([`TOKEN2_DEFAULT_MGMT_KEY`])
/// rather than mimicking YubiKey's. The empty-slice version is the "from the
/// very first version" sentinel also used by [`YUBIKEY_APPLET_VERDICTS`]'s
/// MoveKey row: it orders at or below every real version (`[] <= anything`),
/// so this entry matches regardless of which applet version Token2 reports.
const TOKEN2_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::InsF8SerialIsBcd,
        PivQuirk::Default9bManagementKey(TOKEN2_DEFAULT_MGMT_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const TOKEN2_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The Swissbit iShield 2 Pro's (`OpenFips201::SwissbitIShield2`) applet-axis
/// known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`] — applet version
///   1.4.1.0 and every earlier version have been observed to reject both.
///   Same single-verdict shape as [`TOKEN2_APPLET_VERDICTS`]'s rows, just
///   with `[1, 4, 1, 0]` as the observed/backward-extending version instead
///   of `[5, 112, 0]`. A version above 1.4.1.0 falls off the end of the row
///   and resolves [`FeatureGate::Unverified`] — the known-unsupported
///   verdict deliberately doesn't extend to a future, untested version.
/// * [`PivExtension::ResetGlobal`] — [`Verdict::KnownUnsupportedSince`] at
///   the universal `[]` version — see [`GENERIC_APPLET_VERDICTS`]'s doc for
///   why.
const SWISSBIT_ISHIELD2_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[1, 4, 1, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[VersionVerdict {
            version: &[1, 4, 1, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const SWISSBIT_ISHIELD2_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// The Swissbit iShield 2 Pro's (`OpenFips201::SwissbitIShield2`) applet-axis
/// quirks. Older devices have been observed to never update GET METADATA's
/// algorithm identifier (tag 0x01): it's stuck at whatever it first reported
/// and doesn't reflect the slot's actual key state, so it must always be
/// ignored while this quirk is set. The empty-slice version on the first
/// entry is the "from the very first version" sentinel (see
/// [`TOKEN2_APPLET_QUIRKS`]'s doc) rather than a specific version this was
/// first observed on — the issue might already have been fixed in an
/// earlier version than what's on record here, but no older test hardware
/// has been available to confirm either way, so this deliberately claims no
/// lower bound. The device actually confirmed clear of it reports applet
/// version 1.4.1.0, but the clearing entry below is keyed to the shorter
/// `[1, 4, 1]` on purpose: under this crate's slice-prefix version ordering
/// a shorter version like `[1, 4, 1]` is "less than" any longer one starting
/// with the same elements (`[1, 4, 1] < [1, 4, 1, 0]`), so `[1, 4, 1]` as a
/// threshold covers both a bare 3-component "1.4.1" report and any of its
/// patch releases, whereas `[1, 4, 1, 0]` itself would not match a device
/// reporting the shorter "1.4.1". Per [`latest_quirks`], entries don't
/// accumulate across each other, only across the two axes, so a version at
/// or above `[1, 4, 1]` picks up this entry's quirk list instead and drops
/// [`PivQuirk::InsF7MetadataAlgorithmInvalid`] — but the default-management-
/// key quirk is repeated on both entries so it survives that clearing.
/// Mimics the YubiKey default management key like most other third-party
/// implementations do.
const SWISSBIT_ISHIELD2_APPLET_QUIRKS: &[VersionQuirks] = &[
    VersionQuirks {
        version: &[],
        quirks: &[
            PivQuirk::InsF7MetadataAlgorithmInvalid,
            PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
        ],
    },
    VersionQuirks {
        version: &[1, 4, 1],
        quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
    },
];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const SWISSBIT_ISHIELD2_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The Thetis PRO FIDO2 Security Key with PinPlex's
/// (`AppletFingerprint::Thetis`) applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`] — applet version
///   5.112.0 and every earlier version have been observed to reject both.
///   Same single-verdict shape as the tables above: `[5, 112, 0]` is both
///   the exact-match verdict and the one [`resolve_in`] extends backward
///   from. A version above 5.112.0 falls off the end of the row and
///   resolves [`FeatureGate::Unverified`] — the known-unsupported verdict
///   deliberately doesn't extend to a future, untested version.
/// * [`PivExtension::ResetGlobal`] — [`Verdict::KnownUnsupportedSince`] at
///   the universal `[]` version — see [`GENERIC_APPLET_VERDICTS`]'s doc for
///   why.
/// * [`PivExtension::GetMetadata`] — [`Verdict::KnownSupported`] pinned to
///   applet version 5.112.0, the only version keyroost has hardware evidence
///   for: a live unit at this version answers GET METADATA. Unlike the
///   MoveKey/DeleteKey rows above — both [`Verdict::KnownUnsupported`] at this
///   same version — this fingerprint mimics some Yubico extension APDUs and
///   not others, so this row's positive result doesn't imply anything about
///   those two. No known-unsupported floor is recorded below 5.112.0, so an
///   older reported version resolves [`FeatureGate::Unverified`] rather than
///   inheriting this verdict backward.
const THETIS_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetMetadata,
        verdicts: &[VersionVerdict {
            version: &[5, 112, 0],
            verdict: Verdict::KnownSupported,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const THETIS_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// The Thetis PRO FIDO2 Security Key with PinPlex's
/// (`AppletFingerprint::Thetis`) applet-axis quirks. Observed at applet
/// version 5.112.0, the only version tested so far. Earlier versions are
/// assumed to encode GET SERIAL's reply the same way rather than confirmed
/// to — no earlier-version hardware has been available to test — so the
/// empty-slice version below is a deliberate "from the very first version"
/// assumption, not a direct observation, using the same sentinel as
/// [`TOKEN2_APPLET_QUIRKS`]'s row. Mimics the YubiKey default management key
/// like most other third-party implementations do.
const THETIS_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::InsF8SerialIsBcd,
        PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const THETIS_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// `ArekinathPivApplet::Generic`'s (<https://github.com/arekinath/PivApplet>)
/// applet-axis known-support table. Identical in shape and version thresholds
/// to [`AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS`] below, kept as two
/// separate tables even though the two fingerprints share one upstream
/// codebase:
///
/// * [`PivExtension::MoveKey`]/[`PivExtension::DeleteKey`] — this applet's
///   own source doesn't implement either in applet version 5.4.0 or any
///   release before it: a [`Verdict::KnownUnsupported`] verdict pinned to
///   `[5, 4, 0]`, extended backward by [`resolve_in`]'s rule to cover every
///   earlier version too. A version above 5.4.0 falls off the end of the row
///   and resolves [`FeatureGate::Unverified`] — the known-unsupported
///   verdict doesn't extend forward to an untested future release.
/// * [`PivExtension::GetMetadata`] — lands in this applet's own source at
///   version 5.3.0: a [`Verdict::KnownUnsupported`] verdict at the
///   empty-slice `[]` sentinel (every version before 5.3.0) and a
///   [`Verdict::KnownSupported`] verdict at `[5, 3, 0]` covering that
///   version and every later one, assumed not to have regressed. As on
///   YubiKey's row, the `[]` sentinel is load-bearing — the verdict above it
///   is known-supported, which says nothing about the versions before it.
/// * [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`] — both land
///   in this applet's own source at version 5.0.0: same shape as
///   [`PivExtension::GetMetadata`] above, a [`Verdict::KnownUnsupported`]
///   verdict at `[]` and a [`Verdict::KnownSupported`] verdict at
///   `[5, 0, 0]`. This fingerprint carries no
///   [`PivQuirk::ResetNeedsManagementAuth`] entry on
///   [`AREKINATH_GENERIC_APPLET_QUIRKS`],
///   so — same as YubiKey and Token2 — RESET doesn't need an authenticated
///   management-key session on this applet either.
/// * [`PivExtension::ResetGlobal`] — [`Verdict::KnownUnsupportedSince`] at
///   the universal `[]` version — see [`GENERIC_APPLET_VERDICTS`]'s doc for
///   why.
const AREKINATH_GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[5, 4, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[VersionVerdict {
            version: &[5, 4, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetMetadata,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 3, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::Reset,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 0, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::SetPinPukRetries,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 0, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const AREKINATH_GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// `ArekinathPivApplet::Generic`'s applet-axis quirks: mimics the YubiKey PIV
/// factory-default management key like most other third-party
/// implementations do. No version-gated quirk observed on this fingerprint.
const AREKINATH_GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const AREKINATH_GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// `ArekinathPivApplet::SwissbitIShield1`'s
/// (<https://github.com/swissbit-eis/PivApplet>) applet-axis known-support
/// table — identical to [`AREKINATH_GENERIC_APPLET_VERDICTS`] above (see its
/// doc for the per-extension reasoning), except every non-[`PivExtension::ResetGlobal`]
/// row here is *additionally* confirmed on a real firmware v3.35.0 device
/// reporting applet version 5.4.0 — past both the 5.0.0 and 5.3.0 thresholds
/// below, so it only confirms the known-supported side of those rows, not
/// the floor.
const AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[5, 4, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[VersionVerdict {
            version: &[5, 4, 0],
            verdict: Verdict::KnownUnsupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetMetadata,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 3, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::Reset,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 0, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::SetPinPukRetries,
        verdicts: &[
            VersionVerdict {
                version: &[],
                verdict: Verdict::KnownUnsupported,
            },
            VersionVerdict {
                version: &[5, 0, 0],
                verdict: Verdict::KnownSupported,
            },
        ],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// `ArekinathPivApplet::SwissbitIShield1`'s applet-axis quirks — shares
/// [`AREKINATH_GENERIC_APPLET_QUIRKS`]'s default-management-key entry above
/// (kept as a separate const even though the two fingerprints share one
/// upstream codebase, the same separation
/// [`AREKINATH_SWISSBIT_ISHIELD1_APPLET_VERDICTS`] uses), plus one quirk this
/// variant doesn't share with `Generic`: [`PivQuirk::ResetLongRunning`] — a
/// real SwissbitIShield1 unit has been observed to take over a minute to
/// complete [`PivExtension::Reset`], a wait long enough to look like a hang
/// if a caller doesn't warn for it up front. Seeded at the universal `[]`
/// version since every applet version sampled so far shares the same slow
/// RESET; narrow this to a specific version floor if a future sample turns
/// out faster.
const AREKINATH_SWISSBIT_ISHIELD1_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
        PivQuirk::ResetLongRunning,
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const AREKINATH_SWISSBIT_ISHIELD1_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// HID Crescendo C2300's applet-axis known-support table:
///
/// * [`PivExtension::DeleteKey`] — [`Verdict::KnownSupported`] at the
///   universal `[]` version: `keyroost_transport::PivSession::delete_key`
///   implements HID's own INJECT PKI KEY (`INS 0xD8`) removal form for this
///   family (`keyroost_piv::fingerprint::hid_crescendo_c2300_delete_key`),
///   so unlike [`PivExtension::MoveKey`] below this is a presence claim, not
///   an absence one — see that function's doc for what's confirmed from
///   HID's own API references versus reconstructed from their generic
///   "zero-length data field removes the key" rule (neither page gives a
///   literal delete example). Same shape [`PivExtension::ResetGlobal`]'s row
///   below uses: a positive claim needs no minimum applet version to gate
///   below, so one `KnownSupported` verdict at `[]` is the whole row.
///   Deliberately **not** shared with [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`]
///   — this is a presence claim tied to two specific, named families'
///   documented command references, not the vendor-wide absence pattern the
///   other rows here lean on; `Generic` keeps resolving
///   [`FeatureGate::Unverified`] for [`PivExtension::DeleteKey`], same as any
///   fingerprint with no entry for it — `PivSession::delete_key` still
///   attempts something sensible for it (see that method's doc); this table
///   only decides what the *UI* shows ahead of time, not what the transport
///   layer is willing to try.
/// * [`PivExtension::MoveKey`] — [`Verdict::KnownUnsupportedSince`] at the
///   universal `[]` version, on a standing-pattern reasoning shared with
///   [`PivExtension::Attest`]/[`PivExtension::GetMetadata`]/
///   [`PivExtension::Reset`]/[`PivExtension::SetPinPukRetries`] below: this
///   family has never attempted to mimic a Yubico extension APDU, building
///   its own proprietary alternatives instead (ACA XAUTH, GET PIV
///   PROPERTIES, RESET CARD). For MOVE KEY specifically there is no HID
///   equivalent at all, documented or otherwise: no ACA command relocates a
///   key between PIV slots. That absence of even a proprietary alternative
///   makes the standing-pattern bet the *only* evidence for this row
///   (contrast GET METADATA below, where the alternative's actual
///   documented shape is additional confirmation), but the same reasoning
///   that justifies [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`] sharing this
///   verdict applies here too. Should a real unit ever turn out to support
///   MOVE KEY after all, this row needs a firmware sample to correct it,
///   exactly like every other verdict here. Deliberately **not** mirrored
///   onto [`PivExtension::DeleteKey`] above — DELETE KEY turned out to have
///   the opposite answer on this family: HID's own INJECT PKI KEY
///   (`INS 0xD8`), sent with a zero-length key-data field, is a genuine,
///   documented alternative, so that row carries [`Verdict::KnownSupported`]
///   instead of leaving the family unlisted. The absence-vs-presence split
///   between the two rows is deliberate, not an oversight: MOVE (relocate a
///   key between slots) and DELETE (remove one in place) aren't the same
///   operation just because Yubico's extension API happens to bundle them
///   under one opcode — HID's proprietary API has no obligation to bundle
///   them the same way, and evidently doesn't.
/// * [`PivExtension::Attest`]/[`PivExtension::GetMetadata`] —
///   [`Verdict::KnownUnsupportedSince`] at the universal `[]` version for
///   both: a live unit reporting applet version `3.0.3.6` (read from its GET
///   PIV PROPERTIES response's tag `0x01` "Applet Version Block" —
///   [`crate::fingerprint::parse_hid_crescendo_version`] — and reported on
///   the *applet* axis despite not coming from Yubico's own GET VERSION
///   extension) has been observed to refuse both extensions outright
///   (`SW = 6D 00`, "instruction not supported"). That alone would only
///   justify an ordinary [`Verdict::KnownUnsupported`] pinned to `3.0.3.6`
///   (or, generalized, the whole `3.0.3.<any>` lineage) — but HID Crescendo
///   has never attempted to implement *any* Yubico extension APDU, building
///   its own proprietary alternatives instead across the whole product
///   line: ACA XAUTH (see
///   `keyroost_transport::PivSession::authenticate_management`) standing in
///   for `GENERAL AUTHENTICATE` on `0x9B`, and this very GET PIV PROPERTIES
///   read standing in for GET METADATA. That standing pattern, not just an
///   absence observed on one firmware, is the reason to expect HID never
///   bothers implementing Yubico's competing extension APDUs on *any*
///   version, observed or not, past or future — exactly what
///   [`Verdict::KnownUnsupportedSince`] is for, hence the universal `[]`
///   version rather than a version-specific one. See
///   [`HID_CRESCENDO_C4000_APPLET_VERDICTS`]'s doc for C4000's own version
///   of this same pair of rows.
/// * [`PivExtension::GetSlotKeyStatus`] — [`Verdict::KnownSupported`] at the
///   universal `[]` version: GET PIV PROPERTIES
///   (`keyroost_transport::PivSession::hid_crescendo_slot_algorithm`, via
///   [`crate::fingerprint::parse_hid_crescendo_slot_key_algorithms`]) names
///   every slot that actually has a key loaded — independent of this same
///   fingerprint's [`PivExtension::GetMetadata`] row above
///   ([`Verdict::KnownUnsupportedSince`]): the two questions (does GET
///   METADATA work; can this fingerprint report slot key status at all)
///   have separate, independently confirmed answers here, unlike every
///   fingerprint with no entry for this extension, where they're the same
///   question — see [`resolve`]'s special-case doc for the mechanics. This
///   extension is deliberately sparse across every table in this module: a
///   fingerprint only gets a [`PivExtension::GetSlotKeyStatus`] entry when
///   it reports slot key status through some *other* channel, independently
///   confirmed and gated on its own terms — entirely unrelated to whatever
///   [`PivExtension::GetMetadata`] says for that same fingerprint.
/// * [`PivExtension::PinManagementAuth`] — [`Verdict::KnownSupported`] at
///   the universal `[]` version: every unit in this family unlocks
///   management functionality directly via PIN VERIFY, with no [`PivQuirk`]
///   needed (unlike YubiKey) — PIN VERIFY *is* the unlock, full stop.
/// * [`PivExtension::Reset`] — [`Verdict::KnownUnsupportedSince`] at the
///   universal `[]` version, on the same standing-pattern reasoning as
///   [`PivExtension::GetMetadata`] above, and a card-wide reset alternative
///   already exists for it
///   (<https://docs.hidglobal.com/crescendo/api/low-level/reset-card.htm>,
///   implemented by `keyroost_transport::PivSession::factory_reset` — see
///   [`PivQuirk::ResetNeedsManagementAuth`], set on
///   [`HID_CRESCENDO_C2300_APPLET_QUIRKS`], and [`PivExtension::ResetGlobal`] below for
///   that same mechanism's own known-support data).
/// * [`PivExtension::SetPinPukRetries`] — [`Verdict::KnownUnsupportedSince`]
///   at the universal `[]` version, on the same standing-pattern reasoning
///   as [`PivExtension::Reset`] above. See
///   [`HID_CRESCENDO_C4000_APPLET_VERDICTS`]'s doc for a caveat specific to
///   that family's row.
/// * [`PivExtension::ResetGlobal`] — [`Verdict::KnownSupported`] at the
///   universal `[]` version: RESET CARD against the ACA instance
///   (`INS 0x38`,
///   <https://docs.hidglobal.com/crescendo/api/low-level/reset-card.htm>) is
///   documented for this family and needs no minimum applet version — the
///   opposite verdict from [`PivExtension::Reset`] above for this same
///   fingerprint: the two extensions are resolved independently, and a
///   device can carry either verdict without the other. Deliberately **not**
///   shared with [`HID_CRESCENDO_GENERIC_APPLET_VERDICTS`]: RESET CARD's own
///   documentation names the C2300 and C4000 families specifically, so
///   unlike [`PivExtension::Reset`] (where every HID Crescendo model shares
///   one "never mimics a Yubico extension APDU" absence to reason from)
///   there is no equivalently general basis here to extend a *presence*
///   claim to a model this data doesn't name.
const HID_CRESCENDO_C2300_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::Attest,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetMetadata,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetSlotKeyStatus,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::PinManagementAuth,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::Reset,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::SetPinPukRetries,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const HID_CRESCENDO_C2300_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// HID Crescendo C2300's applet-axis quirks. This fingerprint doesn't
/// support [`PivExtension::Reset`] at all (see [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]'s
/// Reset row) — [`PivQuirk::ResetNeedsManagementAuth`] here describes its
/// *replacement* mechanism instead (RESET CARD against the ACA instance,
/// [`PivExtension::ResetGlobal`] — see that same const's ResetGlobal row),
/// implemented by `keyroost_transport::PivSession::factory_reset` (see this
/// quirk's own doc). HID Crescendo has no standard PIV management key at
/// all — its "default key" is XAUTH key 1's documented all-zero
/// factory-delivery value ([`HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY`]), seeded
/// here too so `keyroost_transport::PivSession`'s post-RESET-CARD restore
/// step reads it back from this table rather than a separately hard-coded
/// constant. Shared verbatim with [`HID_CRESCENDO_C4000_APPLET_QUIRKS`]/
/// [`HID_CRESCENDO_GENERIC_APPLET_QUIRKS`] below — all three sub-fingerprints
/// get this row, same as [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]'s Reset row
/// — see its doc for why `Generic` is included alongside the two named
/// models. (Unlike this quirk, that same const's ResetGlobal row
/// deliberately does NOT extend to `Generic` — see that doc for why the two
/// don't follow the same rule here.)
const HID_CRESCENDO_C2300_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::ResetNeedsManagementAuth,
        PivQuirk::Default9bManagementKey(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const HID_CRESCENDO_C2300_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// HID Crescendo C4000's applet-axis known-support table — same shape and
/// reasoning throughout as [`HID_CRESCENDO_C2300_APPLET_VERDICTS`] (see its
/// doc for the per-extension detail), with two differences:
///
/// * [`PivExtension::Attest`]/[`PivExtension::GetMetadata`] here are
///   **assumed from documentation, not confirmed on hardware: no C4000 test
///   device has been available.**
///   <https://docs.hidglobal.com/crescendo/api/c4000/get-piv-properties.htm>
///   gives no indication this family gained support for Yubico's
///   non-standard extension APDUs either — the C4000 GET PIV PROPERTIES
///   command is itself HID's own proprietary replacement for the same
///   information GET METADATA would carry, which is already reason enough
///   to expect Yubico's extension is absent here too. Should a real C4000 —
///   or, for that matter, C2300 — unit ever turn out to support either
///   extension after all, this row needs a firmware sample to correct it,
///   exactly like every other verdict here.
/// * [`PivExtension::SetPinPukRetries`] — this family's SDK specifically
///   does document a method that in principle covers this ground —
///   `UpdatePINProperties`
///   (<https://docs.hidglobal.com/hid-crescendo-sdk-v2.1/API%20references/html/classCrescendoDLL_1_1SDKCore.html#a0d787ce0adb6ddf90f14772485af9e3e>)
///   — but its APDU-level wire format is undocumented, so there is no
///   keyroost implementation to gate on: this row blocks C4000 for that
///   reason (no implementation), not because HID has no mechanism for it at
///   all.
/// * [`PivExtension::ResetGlobal`]'s RESET CARD reference
///   (<https://docs.hidglobal.com/crescendo/api/c4000/reset-card.htm>) is
///   C4000's own page, distinct from (but equivalent to) C2300's.
const HID_CRESCENDO_C4000_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::DeleteKey,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::Attest,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetMetadata,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetSlotKeyStatus,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::PinManagementAuth,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::Reset,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::ResetGlobal,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::SetPinPukRetries,
        // C4000's SDK docs a method that in principle covers the same
        // ground (`UpdatePINProperties`), but its APDU-level wire format is
        // undocumented, so there is no keyroost implementation to gate on
        // yet — see this table's doc comment.
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const HID_CRESCENDO_C4000_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// HID Crescendo C4000's applet-axis quirks — same row as
/// [`HID_CRESCENDO_C2300_APPLET_QUIRKS`] above; see its doc.
const HID_CRESCENDO_C4000_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::ResetNeedsManagementAuth,
        PivQuirk::Default9bManagementKey(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const HID_CRESCENDO_C4000_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// HID Crescendo Generic's (matched via select identity only — neither C2300
/// nor C4000 applies) applet-axis known-support table:
///
/// * [`PivExtension::MoveKey`], [`PivExtension::Reset`],
///   [`PivExtension::SetPinPukRetries`] — [`Verdict::KnownUnsupportedSince`]
///   at the universal `[]` version, shared with
///   [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]/[`HID_CRESCENDO_C4000_APPLET_VERDICTS`]:
///   the reasoning ("never implements a Yubico extension APDU, always ships
///   its own") is about the vendor's pattern across the whole product line,
///   not about a specific tested model, the same broadening
///   `keyroost_piv::fingerprint`'s ACA AID doc applies to the
///   transport-level XAUTH fallback.
/// * [`PivExtension::GetSlotKeyStatus`] — [`Verdict::KnownSupported`] at the
///   universal `[]` version, shared with the two named models for the same
///   vendor-wide-pattern reasoning: this is a property of the GET PIV
///   PROPERTIES mechanism itself (present, in some form, across the whole
///   product line), not a claim tied to two specifically named,
///   individually tested models.
/// * No entries for [`PivExtension::DeleteKey`] (the C2300/C4000 presence
///   claim isn't general enough to extend here — see
///   [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]'s doc), [`PivExtension::Attest`],
///   [`PivExtension::GetMetadata`], [`PivExtension::PinManagementAuth`], or
///   [`PivExtension::ResetGlobal`] (see that extension's bullet on
///   [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]'s doc for why a presence claim
///   doesn't reach `Generic`).
const HID_CRESCENDO_GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[
    ExtensionVerdicts {
        extension: PivExtension::MoveKey,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::GetSlotKeyStatus,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownSupported,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::Reset,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
    ExtensionVerdicts {
        extension: PivExtension::SetPinPukRetries,
        verdicts: &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }],
    },
];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const HID_CRESCENDO_GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// HID Crescendo Generic's applet-axis quirks — same row as
/// [`HID_CRESCENDO_C2300_APPLET_QUIRKS`] above; see its doc for why `Generic`
/// gets the same row as the two named models here.
const HID_CRESCENDO_GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[
        PivQuirk::ResetNeedsManagementAuth,
        PivQuirk::Default9bManagementKey(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY),
    ],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const HID_CRESCENDO_GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// [`AppletFingerprint::Generic`]'s applet-axis known-support table — a
/// single [`PivExtension::ResetGlobal`] entry, [`Verdict::KnownUnsupportedSince`]
/// at the universal `[]` version. Every non-HID-Crescendo fingerprint's table
/// carries this same entry — deliberately explicit rather than left absent
/// (which would resolve [`FeatureGate::Unverified`], same as any fingerprint
/// with no entry for this extension): `PivSession::factory_reset` checks
/// this gate *first*, ahead of [`PivExtension::Reset`]'s own shape — an
/// `Unverified` default here would make a *non*-HID-Crescendo device with a
/// genuinely working [`PivExtension::Reset`] path (e.g. the PIN/PUK-burn
/// convention) attempt HID's ACA RESET CARD mechanism first instead, fail
/// (there's no such applet on that card), and never fall through to the
/// mechanism that would have worked. An explicit
/// [`Verdict::KnownUnsupportedSince`] here closes that: every fingerprint
/// that isn't HID Crescendo is a flat "no" on this axis, not "no data yet".
/// This is why [`YUBIKEY_APPLET_VERDICTS`], [`TOKEN2_APPLET_VERDICTS`],
/// [`SWISSBIT_ISHIELD2_APPLET_VERDICTS`], [`THETIS_APPLET_VERDICTS`], and
/// both `ArekinathPivApplet` tables above each also carry their own explicit
/// [`PivExtension::ResetGlobal`] entry instead of being left absent, and why
/// [`AUTHENTREND_ATKEY_APPLET_VERDICTS`], [`FEITIAN_APPLET_VERDICTS`],
/// [`IDPRIME_APPLET_VERDICTS`], [`TRUSSED_NITROKEY_APPLET_VERDICTS`],
/// [`OPENFIPS201_GENERIC_APPLET_VERDICTS`], and [`UTRUST_APPLET_VERDICTS`]
/// below are each a single-entry table with exactly this same row.
const GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extension: PivExtension::ResetGlobal,
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// [`AppletFingerprint::Generic`]'s applet-axis quirks. No more specific
/// fingerprint matched, but a device that speaks plain PIV with nothing else
/// recognisable about it is, in practice, overwhelmingly likely to ship the
/// same YubiKey-mimicked default every other unrecognised third-party
/// implementation does.
const GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Authentrend's ATkey's applet-axis known-support table — see
/// [`GENERIC_APPLET_VERDICTS`]'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry.
const AUTHENTREND_ATKEY_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extension: PivExtension::ResetGlobal,
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const AUTHENTREND_ATKEY_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Authentrend's ATkey's applet-axis quirks: mimics the YubiKey PIV
/// factory-default management key like most other third-party
/// implementations do. No version-gated quirk observed on this fingerprint.
const AUTHENTREND_ATKEY_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const AUTHENTREND_ATKEY_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Feitian's applet-axis known-support table — see
/// [`GENERIC_APPLET_VERDICTS`]'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry.
const FEITIAN_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extension: PivExtension::ResetGlobal,
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const FEITIAN_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Feitian's applet-axis quirks: this vendor ships its own vendor-specific
/// PIV factory-default management key rather than mimicking YubiKey's — see
/// [`FEITIAN_DEFAULT_MGMT_KEY`]'s doc.
const FEITIAN_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(FEITIAN_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const FEITIAN_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Gemalto/Thales IDPrime's applet-axis known-support table — see
/// [`GENERIC_APPLET_VERDICTS`]'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry.
const IDPRIME_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extension: PivExtension::ResetGlobal,
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const IDPRIME_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Gemalto/Thales IDPrime's applet-axis quirks — empty: no quirks known for
/// this fingerprint yet, unlike most other fingerprints in this module,
/// which at least mimic a known default management key.
const IDPRIME_APPLET_QUIRKS: &[VersionQuirks] = &[];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const IDPRIME_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The Trussed-based Nitrokey's (`Trussed::NitroKey`) applet-axis
/// known-support table — see [`GENERIC_APPLET_VERDICTS`]'s doc for why this
/// fingerprint gets an explicit [`PivExtension::ResetGlobal`] entry.
const TRUSSED_NITROKEY_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extension: PivExtension::ResetGlobal,
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const TRUSSED_NITROKEY_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// The Trussed-based Nitrokey's (`Trussed::NitroKey`) applet-axis quirks. The
/// Trussed `piv-authenticator`'s own default management key is the same
/// YubiKey-standard value seeded here, hard-coded as `DEFAULT_MANAGEMENT_KEY`
/// in its `constants.rs` —
/// <https://github.com/trussed-dev/piv-authenticator/blob/main/src/constants.rs>.
/// Only `NitroKey` is fingerprinted today (see that variant's doc), but the
/// value is a property of the shared Trussed applet code, not a
/// Nitrokey-specific customization, so any future `TrussedVariant` seeded
/// here should get its own const with this same row.
const TRUSSED_NITROKEY_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const TRUSSED_NITROKEY_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// `OpenFips201::Generic`'s applet-axis known-support table — see
/// [`GENERIC_APPLET_VERDICTS`]'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry. Distinct from
/// [`SWISSBIT_ISHIELD2_APPLET_VERDICTS`] above, which additionally carries
/// MOVE KEY/DELETE KEY data this generic OpenFIPS201 fingerprint has none of.
const OPENFIPS201_GENERIC_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extension: PivExtension::ResetGlobal,
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const OPENFIPS201_GENERIC_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// `OpenFips201::Generic`'s applet-axis quirks — empty: no quirks known for a
/// generic OpenFIPS201 implementation yet. Distinct from
/// [`SWISSBIT_ISHIELD2_APPLET_QUIRKS`] above, which is a specific
/// OpenFIPS201-based product with its own observed quirks.
const OPENFIPS201_GENERIC_APPLET_QUIRKS: &[VersionQuirks] = &[];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const OPENFIPS201_GENERIC_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// Identiv/Hirsch's uTrust's applet-axis known-support table — see
/// [`GENERIC_APPLET_VERDICTS`]'s doc for why this fingerprint gets an
/// explicit [`PivExtension::ResetGlobal`] entry.
const UTRUST_APPLET_VERDICTS: &[ExtensionVerdicts] = &[ExtensionVerdicts {
    extension: PivExtension::ResetGlobal,
    verdicts: &[VersionVerdict {
        version: &[],
        verdict: Verdict::KnownUnsupportedSince,
    }],
}];

/// See [`YUBIKEY_FIRMWARE_VERDICTS`]'s doc — empty.
const UTRUST_FIRMWARE_VERDICTS: &[ExtensionVerdicts] = &[];

/// Identiv/Hirsch's uTrust's applet-axis quirks: mimics the YubiKey PIV
/// factory-default management key like most other third-party
/// implementations do. No version-gated quirk observed on this fingerprint.
const UTRUST_APPLET_QUIRKS: &[VersionQuirks] = &[VersionQuirks {
    version: &[],
    quirks: &[PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)],
}];

/// See [`YUBIKEY_FIRMWARE_QUIRKS`]'s doc — empty.
const UTRUST_FIRMWARE_QUIRKS: &[VersionQuirks] = &[];

/// The UI-facing resolution of a [`PivExtension`] against a live applet,
/// produced by [`resolve`]. Not `#[non_exhaustive]`: it is a closed
/// three-way outcome and every caller is expected to render all three
/// (enable / enable-and-flag / dim) rather than fall through a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureGate {
    /// Enable the control, no warning: the extension is known-supported at the
    /// reported version, or at an earlier one and assumed not to have
    /// regressed.
    Supported,
    /// Enable the control, but flag it: keyroost has no known-support data for
    /// this fingerprint, none at or below the reported version, no reported
    /// version to match, or only a known-unsupported verdict old enough that a later
    /// firmware may have added the extension. See [`Self::UNVERIFIED_SUFFIX`].
    Unverified,
    /// Disable the control (dimmed): a known-unsupported verdict covers the reported
    /// version, so the extension is known to be unsupported here.
    Unsupported,
}

impl FeatureGate {
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unverified`](Self::Unverified): the device has no
    /// known-support data, so support can't be confirmed either way.
    pub const UNVERIFIED_SUFFIX: &'static str =
        "This device is unverified; the operation may fail.";
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unsupported`](Self::Unsupported): a known-unsupported verdict covers
    /// this device's version.
    pub const INCOMPATIBLE_SUFFIX: &'static str = "This device is known to be incompatible.";
}

/// Resolve `extension` for an applet fingerprinted as `fingerprint`, reporting
/// `applet_version` (the PIV applet's own version bytes) and/or
/// `firmware_version` (the device firmware's version bytes) — either or both
/// `None` when the card never reported that one.
///
/// `applet_version` is queried against [`applet_verdicts`] and
/// `firmware_version` against [`firmware_verdicts`], **with
/// identical per-axis lookup semantics**:
///
/// 1. The version is `None` → that axis is [`FeatureGate::Unverified`]
///    (nothing to version-match).
/// 2. No known-support row for `fingerprint` on that axis →
///    [`FeatureGate::Unverified`] (support unknown; don't block).
/// 3. A row exists: take the verdict with the greatest version `<=` the
///    reported version. If there is none — the reported version is older
///    than every verdict on record — fall back to the row's *first* (lowest)
///    verdict, i.e. the nearest one *above* the reported version:
///    * known-unsupported → [`FeatureGate::Unsupported`]: a feature known not to
///      work at that version is assumed not to work at any earlier, untested
///      version either — the backward mirror of the "assumed not to have
///      regressed" forward extension a known-supported verdict gets below;
///    * known-supported, or known-unsupported-since → [`FeatureGate::Unverified`]:
///      neither says anything about the versions before it, so there's
///      nothing to extend backward.
///
///    Otherwise, with a verdict at or below the reported version in hand:
///    * known-supported → [`FeatureGate::Supported`] (covers both an exact-version
///      match and an earlier known-supported verdict assumed not to have regressed);
///    * known-unsupported-since → [`FeatureGate::Unsupported`] unconditionally
///      (covers both an exact-version match and an earlier one) — the mirror
///      image of known-supported's forward extension, for a feature with a
///      standing reason to expect it never comes back (see
///      [`Verdict::KnownUnsupportedSince`]'s doc);
///    * known-unsupported, verdict version **equals** the reported version →
///      [`FeatureGate::Unsupported`];
///    * known-unsupported, verdict version **below** the reported version, and it is
///      the last (highest) verdict in the row → [`FeatureGate::Unverified`]:
///      the known-unsupported verdict may predate a firmware that added the extension;
///    * known-unsupported, verdict version **below** the reported version, but a
///      later verdict exists (for a version above this one's) → the row's
///      known-unsupported knowledge brackets this version, so it is treated as
///      authoritative: [`FeatureGate::Unsupported`].
///
/// The two per-axis outcomes are then combined, in order:
///
/// 1. Either axis is [`FeatureGate::Unsupported`] → combined result is
///    [`FeatureGate::Unsupported`] (a known-incompatible verdict on either
///    axis blocks the control).
/// 2. Else, either axis is [`FeatureGate::Supported`] → combined result is
///    [`FeatureGate::Supported`].
/// 3. Else → combined result is [`FeatureGate::Unverified`].
///
/// This means when only one of `applet_version`/`firmware_version` carries
/// data for `fingerprint`, the other axis resolves to
/// [`FeatureGate::Unverified`] and — per the rule above — simply doesn't
/// change the outcome, so the combined result equals the one axis that has an
/// opinion.
///
/// **One special case, ahead of all of the above:**
/// [`PivExtension::GetSlotKeyStatus`] falls through entirely to
/// `resolve(`[`PivExtension::GetMetadata`]`, fingerprint, applet_version,
/// firmware_version)` whenever `applet_verdicts` carries no
/// [`PivExtension::GetSlotKeyStatus`] entry for `fingerprint` at all — not the
/// ordinary step-2 [`FeatureGate::Unverified`] default every other extension
/// gets in that situation. This is deliberate, not a workaround: GET
/// METADATA's `algorithm` field *is* how slot-key-status is provided on every
/// fingerprint that doesn't have its own [`PivExtension::GetSlotKeyStatus`]
/// entry, so "no entry here" genuinely means "ask [`PivExtension::GetMetadata`]
/// instead", not "no data, assume unverified". A fingerprint that *does*
/// have an entry (today: HID Crescendo, which provides this a different way —
/// see [`HID_CRESCENDO_C2300_APPLET_VERDICTS`]'s doc) is resolved through the ordinary per-axis
/// machinery below, exactly like every other extension, and never
/// consults [`PivExtension::GetMetadata`] at all.
#[must_use]
pub fn resolve(
    extension: PivExtension,
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> FeatureGate {
    if extension == PivExtension::GetSlotKeyStatus
        && applet_verdicts(fingerprint, PivExtension::GetSlotKeyStatus).is_none()
    {
        return resolve(
            PivExtension::GetMetadata,
            fingerprint,
            applet_version,
            firmware_version,
        );
    }
    let applet_gate = resolve_in(applet_verdicts(fingerprint, extension), applet_version);
    let firmware_gate = resolve_in(firmware_verdicts(fingerprint, extension), firmware_version);
    combine(applet_gate, firmware_gate)
}

/// Combine the two per-axis [`FeatureGate`]s into one, per the rule documented
/// on [`resolve`]: [`FeatureGate::Unsupported`] wins outright; otherwise
/// [`FeatureGate::Supported`] wins; otherwise [`FeatureGate::Unverified`].
#[must_use]
fn combine(a: FeatureGate, b: FeatureGate) -> FeatureGate {
    match (a, b) {
        (FeatureGate::Unsupported, _) | (_, FeatureGate::Unsupported) => FeatureGate::Unsupported,
        (FeatureGate::Supported, _) | (_, FeatureGate::Supported) => FeatureGate::Supported,
        (FeatureGate::Unverified, FeatureGate::Unverified) => FeatureGate::Unverified,
    }
}

/// [`resolve`]'s per-axis lookup, given the (fingerprint, extension) pair's
/// verdicts already looked up via [`applet_verdicts`]/[`firmware_verdicts`] —
/// `None` when there were none. Taking the verdicts directly, rather than a
/// table plus the keys to look them up with, also lets a test supply its own
/// synthetic verdicts without wiring a row into the const tables.
fn resolve_in(verdicts: Option<&[VersionVerdict]>, version: Option<&[u8]>) -> FeatureGate {
    let Some(version) = version else {
        return FeatureGate::Unverified;
    };
    let Some(verdicts) = verdicts else {
        return FeatureGate::Unverified;
    };
    let Some(idx) = verdicts.iter().rposition(|v| v.version <= version) else {
        // The reported version is older than every verdict on record. Fall
        // back to the nearest one *above* it — `verdicts[0]`, since rows are
        // sorted ascending — and, if that verdict is `KnownUnsupported`,
        // extend it backward: a feature known not to work at that version is
        // assumed not to work at any earlier, untested version either. A
        // `KnownSupported` verdict, by contrast, says nothing about versions
        // before it — and neither does a `KnownUnsupportedSince` one, by the
        // same "says nothing about the past" rule that gives it its name; it
        // falls into the same `_` arm as `KnownSupported` here.
        return match verdicts.first() {
            Some(VersionVerdict {
                verdict: Verdict::KnownUnsupported,
                ..
            }) => FeatureGate::Unsupported,
            _ => FeatureGate::Unverified,
        };
    };
    let chosen = &verdicts[idx];
    match chosen.verdict {
        // Known supported at or below the reported version — and assumed not
        // to have regressed in any newer version we have no verdict for.
        Verdict::KnownSupported => FeatureGate::Supported,
        // A known-unsupported verdict for exactly this version: a direct observation
        // that this build lacks the extension. Nothing softens that.
        Verdict::KnownUnsupported if chosen.version == version => FeatureGate::Unsupported,
        // A known-unsupported verdict from an *older* version with nothing newer on
        // record: the extension may have been added in a firmware we haven't
        // observed, so warn rather than block.
        Verdict::KnownUnsupported if idx + 1 == verdicts.len() => FeatureGate::Unverified,
        // A known-unsupported verdict from an older version, but a later verdict exists
        // (for a version above this applet's): our known-unsupported knowledge
        // brackets this version, so treat it as authoritative and block.
        Verdict::KnownUnsupported => FeatureGate::Unsupported,
        // `KnownUnsupportedSince` at or below the reported version — and,
        // mirroring `KnownSupported`'s forward extension exactly, assumed to
        // *stay* unsupported in any newer version we have no verdict for.
        // Unlike plain `KnownUnsupported` above, this never softens to
        // `Unverified` just for being the row's last (highest) verdict — the
        // whole point of this variant is that there's a standing reason not
        // to expect a later firmware to add the extension back.
        Verdict::KnownUnsupportedSince => FeatureGate::Unsupported,
    }
}

/// The entry in `quirks` with the greatest [`VersionQuirks::version`] `<=`
/// `version`, if any — the "current" quirks entry for that version, ignoring
/// anything with a higher version on record. Same lookup rule as step 3 of
/// [`resolve_in`], but there's no known-support reasoning to apply once the
/// entry is found: quirks are taken as-is.
fn latest_quirks<'a>(quirks: &'a [VersionQuirks], version: &[u8]) -> Option<&'a VersionQuirks> {
    let idx = quirks.iter().rposition(|v| v.version <= version)?;
    Some(&quirks[idx])
}

/// Resolve the set of [`PivQuirk`]s active for an applet fingerprinted as
/// `fingerprint`, reporting `applet_version` and/or `firmware_version` —
/// either or both `None` when the card never reported that one:
///
/// 1. If `applet_version` is available, take `fingerprint`'s [`applet_quirks`]
///    entry with the highest version `<=` `applet_version` (if any).
/// 2. If `firmware_version` is available, take `fingerprint`'s
///    [`firmware_quirks`] entry with the highest version `<=`
///    `firmware_version` (if any).
/// 3. Merge the [`VersionQuirks::quirks`] from whichever of (1)/(2) matched
///    into a single set.
///
/// Unlike [`resolve`], there's no known-support reasoning here: each
/// axis contributes at most one entry's quirks, and quirks only ever
/// accumulate — nothing in this table can suppress a quirk another entry
/// added.
#[must_use]
pub fn resolve_quirks(
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    resolve_quirks_in(
        applet_quirks(fingerprint),
        firmware_quirks(fingerprint),
        applet_version,
        firmware_version,
    )
}

/// [`resolve_quirks`] against explicit applet/firmware quirk lists, so a
/// test can supply its own without wiring one into the const tables — same
/// role [`resolve_in`] plays for [`resolve`].
fn resolve_quirks_in(
    applet_entries: &[VersionQuirks],
    firmware_entries: &[VersionQuirks],
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    let mut quirks = BTreeSet::new();
    if let Some(version) = applet_version {
        if let Some(entry) = latest_quirks(applet_entries, version) {
            quirks.extend(entry.quirks.iter().copied());
        }
    }
    if let Some(version) = firmware_version {
        if let Some(entry) = latest_quirks(firmware_entries, version) {
            quirks.extend(entry.quirks.iter().copied());
        }
    }
    quirks
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- User-facing wording: requirement() + a suffix -------------------

    #[test]
    fn requirement_is_distinct_per_extension_and_composes_with_a_suffix() {
        let reqs = [
            PivExtension::MoveKey.requirement(),
            PivExtension::DeleteKey.requirement(),
            PivExtension::GetMetadata.requirement(),
            PivExtension::GetSlotKeyStatus.requirement(),
            PivExtension::Attest.requirement(),
            PivExtension::PinManagementAuth.requirement(),
            PivExtension::Reset.requirement(),
            PivExtension::ResetGlobal.requirement(),
            PivExtension::SetPinPukRetries.requirement(),
        ];
        for (i, a) in reqs.iter().enumerate() {
            for b in &reqs[i + 1..] {
                assert_ne!(a, b);
            }
            // Ends a sentence, so "<req> <suffix>" reads as two.
            assert!(a.ends_with('.'), "{a:?}");
        }
        for suffix in [
            FeatureGate::UNVERIFIED_SUFFIX,
            FeatureGate::INCOMPATIBLE_SUFFIX,
        ] {
            assert!(suffix.ends_with('.'), "{suffix:?}");
            assert!(!suffix.is_empty());
        }
    }

    // --- YubiKey: the seeded 5.7 gate, both extensions -------------------

    #[test]
    fn yubikey_below_5_7_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            // Matches the known-unsupported sentinel verdict (version `[]`), which is
            // not the last verdict, so the known-unsupported verdict is authoritative.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 6, 0]), None),
                FeatureGate::Unsupported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[4, 3, 7]), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn yubikey_5_7_and_newer_is_supported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            // Bare [5, 7] clears the bar: `[5, 7] <= [5, 7]`.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 7]), None),
                FeatureGate::Supported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[5, 7, 4]), None),
                FeatureGate::Supported
            );
            // A later version with no verdict of its own falls to the [5, 7]
            // known-supported verdict, assumed not to have regressed.
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, Some(&[6, 0, 0]), None),
                FeatureGate::Supported
            );
        }
    }

    #[test]
    fn yubikey_without_a_reported_version_is_unverified() {
        assert_eq!(
            resolve(
                PivExtension::MoveKey,
                AppletFingerprint::YubiKey,
                None,
                None
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn firmware_version_is_ignored_when_the_extension_has_no_firmware_axis_data() {
        // Today no `PivExtension` has firmware-version verdicts, so any
        // firmware_version — however implausible — leaves the applet-version
        // axis as the sole opinion.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::YubiKey,
                    Some(&[5, 7]),
                    Some(&[9, 9, 9]),
                ),
                FeatureGate::Supported
            );
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::YubiKey,
                    Some(&[5, 6]),
                    Some(&[9, 9, 9]),
                ),
                FeatureGate::Unsupported
            );
        }
    }

    // --- Token2: the seeded 5.112.0 known-unsupported verdict, both extensions ---

    #[test]
    fn token2_5_112_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[5, 112, 0]), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn token2_older_versions_are_also_unsupported() {
        // No verdict at or below these versions, so `resolve_in` falls back
        // to the row's only (and therefore nearest-above) verdict: the
        // 5.112.0 known-unsupported verdict, extended backward.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[5, 111, 0]), None),
                FeatureGate::Unsupported
            );
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[0]), None),
                FeatureGate::Unsupported
            );
        }
    }

    #[test]
    fn token2_newer_versions_are_unverified_not_known_unsupported() {
        // No known-supported verdict on this row, and 5.112.0 is the last (highest)
        // entry, so — per `resolve_in`'s "trailing stale known-unsupported" rule — a
        // version above it doesn't inherit the verdict: the known-unsupported verdict is
        // deliberately never treated as covering a version it hasn't
        // actually observed.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Token2, Some(&[5, 113, 0]), None),
                FeatureGate::Unverified
            );
        }
    }

    // --- Thetis PRO FIDO2 Security Key with PinPlex: the seeded 5.112.0 -
    // --- known-unsupported verdict, both extensions -----------------------

    #[test]
    fn thetis_5_112_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[5, 112, 0]), None),
                FeatureGate::Unsupported
            );
            // No verdict at or below this version, so `resolve_in` falls
            // back to the row's only verdict — the 5.112.0 known-unsupported verdict,
            // extended backward.
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[0]), None),
                FeatureGate::Unsupported
            );
            // Same trailing-known-unsupported softening above the highest verdict.
            assert_eq!(
                resolve(ext, AppletFingerprint::Thetis, Some(&[5, 113, 0]), None),
                FeatureGate::Unverified
            );
        }
    }

    // --- Swissbit iShield 2 Pro: the bracketed <= 1.4.1.0 known-unsupported verdict ---

    #[test]
    fn swissbit_ishield2_at_or_below_1_4_1_0_is_unsupported() {
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
            // The exact observed version: known-unsupported via the direct-match
            // rule.
            assert_eq!(
                resolve(ext, fp, Some(&[1, 4, 1, 0]), None),
                FeatureGate::Unsupported
            );
            // Anything older: no verdict at or below it, so `resolve_in`
            // falls back to the row's only verdict — the `[1, 4, 1, 0]`
            // known-unsupported verdict, extended backward rather than softening to
            // `Unverified`.
            for older in [&[0][..], &[1][..], &[1, 4, 0][..]] {
                assert_eq!(
                    resolve(ext, fp, Some(older), None),
                    FeatureGate::Unsupported
                );
            }
        }
    }

    #[test]
    fn swissbit_ishield2_above_1_4_1_0_is_unverified_not_known_unsupported() {
        // The known-unsupported verdict deliberately doesn't extend to a version keyroost
        // hasn't actually observed: `[1, 4, 1, 0]` is the last verdict in
        // the row, so anything strictly newer softens to `Unverified` per
        // `resolve_in`'s trailing-known-unsupported rule.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            let fp = AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2);
            for newer in [&[1, 4, 1, 1][..], &[1, 5, 0][..], &[2, 0][..]] {
                assert_eq!(resolve(ext, fp, Some(newer), None), FeatureGate::Unverified);
            }
        }
    }

    #[test]
    fn swissbit_ishield2_other_openfips201_variant_is_unverified() {
        // The row is keyed to the SwissbitIShield2 sub-fingerprint
        // specifically — the generic OpenFIPS201 variant carries no data.
        for ext in [PivExtension::MoveKey, PivExtension::DeleteKey] {
            assert_eq!(
                resolve(
                    ext,
                    AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                    Some(&[1, 4, 1, 0]),
                    None,
                ),
                FeatureGate::Unverified
            );
        }
    }

    // --- HID Crescendo: MOVE KEY only, `KnownUnsupportedSince` ------------

    #[test]
    fn hid_crescendo_move_key_is_known_unsupported_since_regardless_of_version() {
        // `Verdict::KnownUnsupportedSince` at the universal `[]` version:
        // unlike a plain `KnownUnsupported` verdict (see the Token2/Swissbit/
        // Thetis tests above), this doesn't soften to `Unverified` for a
        // version newer than anything on the row — every *reported* version
        // matches it. (A missing version report is a separate case, covered
        // below: `resolve_in` returns `Unverified` before it even looks at
        // the table when there's no version to match against at all — same
        // as `yubikey_without_a_reported_version_is_unverified`.)
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[99][..]] {
                assert_eq!(
                    resolve(PivExtension::MoveKey, fp, Some(version), Some(version)),
                    FeatureGate::Unsupported,
                    "{variant:?} at {version:?}"
                );
            }
        }
    }

    #[test]
    fn hid_crescendo_move_key_without_a_reported_version_is_unverified() {
        // Same "no version to compare against at all" rule every other
        // extension follows — see `yubikey_without_a_reported_version_is_unverified`.
        // `Verdict::KnownUnsupportedSince` changes how a *reported* version
        // resolves, not whether a version is required in the first place.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            assert_eq!(
                resolve(
                    PivExtension::MoveKey,
                    AppletFingerprint::HidCrescendo(variant),
                    None,
                    None,
                ),
                FeatureGate::Unverified
            );
        }
    }

    // --- HID Crescendo: DELETE KEY only, `KnownSupported` on C2300/C4000 --

    #[test]
    fn hid_crescendo_c2300_c4000_delete_key_is_known_supported_regardless_of_version() {
        // `Verdict::KnownSupported` at the universal `[]` version: a
        // reported version, present or absent, doesn't change the verdict —
        // unlike a version-gated row (contrast the YubiKey tests above),
        // there's nothing to fall below or above. Still needs *some*
        // reported version to reach the row at all — see
        // `resolve_in`: `applet_version: None` returns `Unverified` before
        // even looking at the table (matches
        // `yubikey_without_a_reported_version_is_unverified`).
        for variant in [HidCrescendoVariant::C2300, HidCrescendoVariant::C4000] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[99][..]] {
                assert_eq!(
                    resolve(PivExtension::DeleteKey, fp, Some(version), Some(version)),
                    FeatureGate::Supported,
                    "{variant:?} at {version:?}"
                );
            }
        }
    }

    #[test]
    fn hid_crescendo_generic_delete_key_carries_no_row_and_stays_unverified() {
        // Deliberately not extended to `Generic` — see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
        // Crescendo DeleteKey bullet: this is a presence claim tied to
        // C2300/C4000's own named API references, not the vendor-wide
        // absence pattern that justifies covering `Generic` on that table's
        // MoveKey/Reset HID Crescendo rows.
        assert_eq!(
            resolve(
                PivExtension::DeleteKey,
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
                Some(&[3, 0, 3, 6]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    // --- No row for the fingerprint -------------------------------------

    #[test]
    fn unknown_fingerprint_is_unverified_regardless_of_version() {
        for version in [None, Some(&[5, 7, 4][..]), Some(&[1, 0][..])] {
            assert_eq!(
                resolve(
                    PivExtension::DeleteKey,
                    AppletFingerprint::Generic,
                    version,
                    version,
                ),
                FeatureGate::Unverified
            );
            // A second, real fingerprint that genuinely carries no MoveKey
            // MoveKey row in any per-fingerprint applet-axis table at all — unlike `AppletFingerprint::Token2`,
            // whose row's single known-unsupported verdict extends backward to
            // resolve `Unsupported` for these same low versions; see
            // `token2_older_versions_are_also_unsupported`. Also unlike
            // HID Crescendo, which now does carry a row on this table — see
            // `hid_crescendo_move_key_is_known_unsupported_since_regardless_of_version`.
            assert_eq!(
                resolve(
                    PivExtension::MoveKey,
                    AppletFingerprint::UTrust,
                    version,
                    version,
                ),
                FeatureGate::Unverified
            );
        }
    }

    // --- combine(): the cross-axis rule -----------------------------------

    #[test]
    fn combine_prefers_unsupported_over_anything_else() {
        assert_eq!(
            combine(FeatureGate::Unsupported, FeatureGate::Supported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine(FeatureGate::Supported, FeatureGate::Unsupported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine(FeatureGate::Unverified, FeatureGate::Unsupported),
            FeatureGate::Unsupported
        );
        assert_eq!(
            combine(FeatureGate::Unsupported, FeatureGate::Unverified),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn combine_prefers_supported_over_unverified() {
        assert_eq!(
            combine(FeatureGate::Supported, FeatureGate::Unverified),
            FeatureGate::Supported
        );
        assert_eq!(
            combine(FeatureGate::Unverified, FeatureGate::Supported),
            FeatureGate::Supported
        );
    }

    #[test]
    fn combine_of_only_unverified_is_unverified() {
        assert_eq!(
            combine(FeatureGate::Unverified, FeatureGate::Unverified),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn combine_is_symmetric_and_idempotent() {
        for gate in [
            FeatureGate::Supported,
            FeatureGate::Unverified,
            FeatureGate::Unsupported,
        ] {
            // Combining a gate with itself is that gate again...
            assert_eq!(combine(gate, gate), gate);
            for other in [
                FeatureGate::Supported,
                FeatureGate::Unverified,
                FeatureGate::Unsupported,
            ] {
                // ...and argument order never matters.
                assert_eq!(combine(gate, other), combine(other, gate));
            }
        }
    }

    // --- The resolve() rules, exercised against a synthetic row ---------

    fn gate(verdicts: &'static [VersionVerdict], version: Option<&[u8]>) -> FeatureGate {
        resolve_in(Some(verdicts), version)
    }

    #[test]
    fn applet_older_than_every_known_supported_verdict_is_unverified() {
        // The nearest verdict above is known-supported, which says nothing about
        // versions before it, so there's nothing to extend backward.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownSupported,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn applet_older_than_every_known_unsupported_verdict_is_unsupported() {
        // The nearest verdict above is known-unsupported: a feature known not to
        // work at that version is assumed not to work at any earlier,
        // untested version either — the backward mirror of
        // `earlier_known_supported_is_assumed_not_to_regress` below.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupported,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn applet_older_than_every_verdict_uses_the_nearest_one_above() {
        // Two verdicts, both above the reported version: the fallback picks
        // the row's first (lowest, i.e. nearest-above) entry, not just any
        // entry — so a known-unsupported verdict further above doesn't leak backward past a
        // known-supported verdict that's nearer.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::KnownSupported,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::KnownUnsupported,
                    },
                ],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn exact_version_known_unsupported_match_is_unsupported() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::KnownUnsupported,
                }],
                Some(&[5, 7]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn trailing_stale_known_unsupported_is_unverified() {
        // Only known-unsupported, from a version below the applet's, and it is the
        // last verdict — the extension might have been added since.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupported,
                }],
                Some(&[5, 4]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn bracketed_known_unsupported_stays_authoritative() {
        // A known-unsupported verdict below the applet's version, with a later verdict above
        // it: keyroost's known-unsupported knowledge brackets the applet version.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::KnownUnsupported,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::KnownSupported,
                    },
                ],
                Some(&[5, 4]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn earlier_known_supported_is_assumed_not_to_regress() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::KnownSupported,
                }],
                Some(&[9, 1, 2]),
            ),
            FeatureGate::Supported
        );
    }

    // --- KnownUnsupportedSince: the mirror image of KnownSupported's -----
    // --- extension direction ----------------------------------------------

    #[test]
    fn applet_older_than_every_known_unsupported_since_verdict_is_unverified() {
        // Same fallback shape as `applet_older_than_every_known_supported_verdict_is_unverified`:
        // the nearest verdict above says nothing about versions before it,
        // so there's nothing to extend backward — unlike plain
        // `KnownUnsupported`, which *would* extend backward here.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupportedSince,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn known_unsupported_since_never_softens_to_unverified_going_forward() {
        // Unlike plain `KnownUnsupported` (see
        // `trailing_stale_known_unsupported_is_unverified`), being the row's
        // last (highest) verdict doesn't soften this to `Unverified` — the
        // whole point of this variant is that it's assumed to stay
        // unsupported indefinitely.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupportedSince,
                }],
                Some(&[9, 9, 9]),
            ),
            FeatureGate::Unsupported
        );
        // Exact match on the verdict's own version, same as the fallback
        // that fires when nothing is strictly below it.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::KnownUnsupportedSince,
                }],
                Some(&[5, 0]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn known_unsupported_since_at_the_universal_empty_version_covers_everything() {
        // `[]` orders at or below every real version, so a lone
        // `KnownUnsupportedSince` verdict there is always the chosen one —
        // never the "older than every verdict" fallback — and, per the test
        // above, never softens going forward either. This is the exact shape
        // `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s GetMetadata/Attest rows use
        // C2300/C4000.
        let verdicts: &[VersionVerdict] = &[VersionVerdict {
            version: &[],
            verdict: Verdict::KnownUnsupportedSince,
        }];
        for version in [&[0][..], &[3, 0, 3, 6][..], &[255, 255, 255][..]] {
            assert_eq!(gate(verdicts, Some(version)), FeatureGate::Unsupported);
        }
    }

    // --- resolve_quirks(): the separate, non-gating quirks axis ----------

    fn quirks(
        applet_entries: &'static [VersionQuirks],
        firmware_entries: &'static [VersionQuirks],
        applet_version: Option<&[u8]>,
        firmware_version: Option<&[u8]>,
    ) -> BTreeSet<PivQuirk> {
        resolve_quirks_in(
            applet_entries,
            firmware_entries,
            applet_version,
            firmware_version,
        )
    }

    #[test]
    fn no_data_on_either_axis_resolves_to_no_quirks() {
        // IdPrime carries no quirk row at all — unlike YubiKey (which since
        // `PinManagementAuthProtected9BKey` has one from applet version 3 on
        // — see `yubikey_pin_management_auth_3_and_newer_is_supported_with_the_protected_key_quirk`)
        // or UTrust (which mimics the YubiKey default management key — see
        // `default_9b_management_key_seeded_fingerprints`).
        assert_eq!(
            resolve_quirks(AppletFingerprint::IdPrime, Some(&[5, 7]), Some(&[5, 7])),
            BTreeSet::new()
        );
    }

    #[test]
    fn quirk_axis_picks_the_highest_matching_version() {
        let entries: &[VersionQuirks] = &[
            VersionQuirks {
                version: &[5, 0],
                quirks: &[PivQuirk::InsF8SerialIsBcd],
            },
            VersionQuirks {
                version: &[5, 7],
                quirks: &[PivQuirk::InsF7MetadataAlgorithmInvalid],
            },
        ];
        // Below every entry: no quirks at all.
        assert_eq!(quirks(entries, &[], Some(&[4, 9]), None), BTreeSet::new());
        // Between the two entries: only the lower one's quirk applies.
        assert_eq!(
            quirks(entries, &[], Some(&[5, 3]), None),
            BTreeSet::from([PivQuirk::InsF8SerialIsBcd])
        );
        // At or above the higher entry: only *its* quirk — entries don't
        // accumulate across each other, only across the two axes.
        assert_eq!(
            quirks(entries, &[], Some(&[6, 0]), None),
            BTreeSet::from([PivQuirk::InsF7MetadataAlgorithmInvalid])
        );
    }

    #[test]
    fn quirks_from_both_axes_merge_into_one_set() {
        let applet_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }];
        let firmware_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF7MetadataAlgorithmInvalid],
        }];
        assert_eq!(
            quirks(
                applet_entries,
                firmware_entries,
                Some(&[1, 0]),
                Some(&[1, 0]),
            ),
            BTreeSet::from([
                PivQuirk::InsF8SerialIsBcd,
                PivQuirk::InsF7MetadataAlgorithmInvalid,
            ])
        );
    }

    #[test]
    fn quirks_ignore_an_axis_with_no_reported_version() {
        let applet_entries: &[VersionQuirks] = &[VersionQuirks {
            version: &[],
            quirks: &[PivQuirk::InsF8SerialIsBcd],
        }];
        assert_eq!(
            quirks(applet_entries, &[], None, Some(&[9, 9])),
            BTreeSet::new()
        );
    }

    #[test]
    fn unknown_fingerprint_has_no_quirks() {
        // IdPrime, again — see `no_data_on_either_axis_resolves_to_no_quirks`
        // for why `Generic` no longer fits this test: it now carries its own
        // `Default9bManagementKey` row (see
        // `default_9b_management_key_seeded_fingerprints`).
        assert_eq!(
            resolve_quirks(AppletFingerprint::IdPrime, Some(&[1, 0]), Some(&[1, 0])),
            BTreeSet::new()
        );
    }

    // --- Token2: the seeded BCD-serial quirk ------------------------------

    #[test]
    fn token2_bcd_serial_quirk_matches_any_reported_applet_version() {
        // The `[]` sentinel orders at or below every real version, so this
        // fires regardless of how old or new the reported version is. Token2
        // also carries its own vendor-specific default management key on the
        // same row — see `default_9b_management_key_seeded_fingerprints`.
        for version in [&[0, 0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(AppletFingerprint::Token2, Some(version), None),
                BTreeSet::from([
                    PivQuirk::InsF8SerialIsBcd,
                    PivQuirk::Default9bManagementKey(TOKEN2_DEFAULT_MGMT_KEY),
                ])
            );
        }
    }

    #[test]
    fn token2_bcd_serial_quirk_needs_a_reported_applet_version() {
        // No applet_version → nothing to version-match against, so the
        // applet axis contributes nothing (same "None → skip" rule as the
        // FeatureGate axis); the firmware axis has no Token2 data at all.
        assert_eq!(
            resolve_quirks(AppletFingerprint::Token2, None, None),
            BTreeSet::new()
        );
    }

    // --- Thetis PRO FIDO2 Security Key with PinPlex: the seeded --------
    // --- BCD-serial quirk --------------------------------------------------

    #[test]
    fn thetis_bcd_serial_quirk_matches_any_reported_applet_version() {
        // The `[]` sentinel orders at or below every real version, so this
        // fires regardless of how old or new the reported version is —
        // including versions below 5.112.0, the only one actually tested;
        // see the row's comment on why that's an assumption, not an
        // observation. Thetis mimics the YubiKey default management key too
        // — see `default_9b_management_key_seeded_fingerprints`.
        for version in [&[0, 0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(AppletFingerprint::Thetis, Some(version), None),
                BTreeSet::from([
                    PivQuirk::InsF8SerialIsBcd,
                    PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
                ])
            );
        }
        assert_eq!(
            resolve_quirks(AppletFingerprint::Thetis, None, None),
            BTreeSet::new()
        );
    }

    // --- Swissbit iShield 2 Pro (OpenFips201): the seeded, then-cleared, -
    // --- GET METADATA algorithm-identifier quirk -------------------------

    #[test]
    fn swissbit_ishield2_metadata_quirk_below_1_4_1() {
        // The sentinel version `[]` matches regardless of how old the
        // reported version is, so this is active from the very first
        // version on record. The default-management-key quirk rides along
        // on the same entry — see
        // `default_9b_management_key_seeded_fingerprints`.
        for version in [&[0][..], &[1][..], &[1, 3, 9][..], &[1, 4, 0][..]] {
            assert_eq!(
                resolve_quirks(
                    AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
                    Some(version),
                    None,
                ),
                BTreeSet::from([
                    PivQuirk::InsF7MetadataAlgorithmInvalid,
                    PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
                ])
            );
        }
    }

    #[test]
    fn swissbit_ishield2_metadata_quirk_cleared_at_1_4_1() {
        // `[1, 4, 1]` covers both a bare 3-component "1.4.1" report and the
        // actually-confirmed-clear 4-component "1.4.1.0" — `[1, 4, 1]`
        // orders below both under slice-prefix comparison. The metadata
        // quirk clears here, but the default-management-key quirk is
        // repeated on this entry too (see the row's comment) and so
        // survives the clearing.
        for version in [
            &[1, 4, 1][..],
            &[1, 4, 1, 0][..],
            &[1, 5, 0][..],
            &[2, 0][..],
        ] {
            assert_eq!(
                resolve_quirks(
                    AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
                    Some(version),
                    None,
                ),
                BTreeSet::from([PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)])
            );
        }
    }

    #[test]
    fn swissbit_ishield2_other_openfips201_variant_has_no_quirk() {
        // The row is keyed to the SwissbitIShield2 sub-fingerprint
        // specifically — the generic OpenFIPS201 variant isn't covered.
        assert_eq!(
            resolve_quirks(
                AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
                Some(&[1]),
                None,
            ),
            BTreeSet::new()
        );
    }

    // --- PivQuirk::Default9bManagementKey: the seeded factory-default -----
    // --- management-key quirk, by fingerprint -----------------------------

    #[test]
    fn default_9b_management_key_seeded_fingerprints() {
        let yubikey_mimics = [
            AppletFingerprint::Generic,
            AppletFingerprint::YubiKey,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
            AppletFingerprint::AuthentrendATKey,
            AppletFingerprint::UTrust,
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
            AppletFingerprint::Trussed(TrussedVariant::NitroKey),
        ];
        for fp in yubikey_mimics {
            assert_eq!(
                default_9b_management_key(&resolve_quirks(fp, Some(&[0]), None)),
                Some(YUBIKEY_DEFAULT_MGMT_KEY),
                "{fp:?}"
            );
        }
        // Thetis carries its own row (with `InsF8SerialIsBcd` alongside it —
        // see `thetis_bcd_serial_quirk_matches_any_reported_applet_version`),
        // so it's checked separately rather than folded into the loop above.
        assert_eq!(
            default_9b_management_key(&resolve_quirks(AppletFingerprint::Thetis, Some(&[0]), None)),
            Some(YUBIKEY_DEFAULT_MGMT_KEY)
        );

        assert_eq!(
            default_9b_management_key(&resolve_quirks(AppletFingerprint::Token2, Some(&[0]), None)),
            Some(TOKEN2_DEFAULT_MGMT_KEY)
        );
        assert_eq!(
            default_9b_management_key(&resolve_quirks(
                AppletFingerprint::Feitian,
                Some(&[0]),
                None
            )),
            Some(FEITIAN_DEFAULT_MGMT_KEY)
        );
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            assert_eq!(
                default_9b_management_key(&resolve_quirks(
                    AppletFingerprint::HidCrescendo(variant),
                    Some(&[0]),
                    None,
                )),
                Some(&HID_CRESCENDO_ACA_FACTORY_XAUTH_KEY[..]),
                "{variant:?}"
            );
        }
    }

    #[test]
    fn default_9b_management_key_applies_below_and_at_yubikey_applet_version_3() {
        // Unlike `PinManagementAuthProtected9BKey` (which only starts at
        // applet version 3), the default management key applies at any
        // reported version, including below 3.
        for version in [&[0][..], &[2, 9][..], &[3][..], &[5, 7][..]] {
            assert_eq!(
                default_9b_management_key(&resolve_quirks(
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None
                )),
                Some(YUBIKEY_DEFAULT_MGMT_KEY),
                "{version:?}"
            );
        }
    }

    #[test]
    fn default_9b_management_key_absent_without_a_seeded_row() {
        for fp in [
            AppletFingerprint::IdPrime,
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
        ] {
            assert_eq!(
                default_9b_management_key(&resolve_quirks(fp, Some(&[0]), None)),
                None,
                "{fp:?}"
            );
        }
    }

    #[test]
    fn default_9b_management_key_absent_without_a_reported_version() {
        // Same "None → skip" rule as every other quirk: with no
        // applet/firmware version reported at all, there's nothing to
        // version-match against, so even a seeded fingerprint resolves no
        // quirks.
        assert_eq!(
            default_9b_management_key(&resolve_quirks(AppletFingerprint::YubiKey, None, None)),
            None
        );
    }

    // --- PivQuirk::ResetLongRunning: SwissbitIShield1's slow RESET ---------

    #[test]
    fn swissbit_ishield1_carries_reset_long_running_at_any_version() {
        // Seeded at the universal `[]` version, so it applies from the
        // lowest reported version on up, alongside the shared
        // default-management-key quirk every other YubiKey-mimicking
        // fingerprint also carries.
        for version in [&[0][..], &[5, 4, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve_quirks(
                    AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
                    Some(version),
                    None,
                ),
                BTreeSet::from([
                    PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY),
                    PivQuirk::ResetLongRunning,
                ]),
                "{version:?}"
            );
        }
    }

    #[test]
    fn arekinath_generic_has_no_reset_long_running_quirk() {
        // The quirk is scoped to the SwissbitIShield1 sub-fingerprint
        // specifically, not the whole ArekinathPivApplet family — `Generic`
        // shares the default-management-key row but not this one.
        assert_eq!(
            resolve_quirks(
                AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
                Some(&[0]),
                None,
            ),
            BTreeSet::from([PivQuirk::Default9bManagementKey(YUBIKEY_DEFAULT_MGMT_KEY)])
        );
    }

    // --- HID Crescendo (C2300 and C4000): GET METADATA/ATTEST known-unsupported --
    // --- by their own GET PIV PROPERTIES version, on the applet axis -------

    #[test]
    fn hid_crescendo_c2300_get_metadata_and_attest_known_unsupported_at_any_version() {
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300);
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            // The one version actually observed (`3.0.3.6`, family byte
            // already stripped by `parse_hid_crescendo_version`) — on the
            // *applet* axis, since it's an applet version despite coming
            // from GET PIV PROPERTIES rather than Yubico's GET VERSION
            // extension.
            assert_eq!(
                resolve(ext, fp, Some(&[3, 0, 3, 6]), None),
                FeatureGate::Unsupported
            );
            // Older and newer versions alike — `KnownUnsupportedSince` at the
            // universal `[]` version makes no exception in either direction,
            // unlike an ordinary `KnownUnsupported` pinned to one build.
            assert_eq!(resolve(ext, fp, Some(&[0]), None), FeatureGate::Unsupported);
            assert_eq!(
                resolve(ext, fp, Some(&[9, 9, 9, 9]), None),
                FeatureGate::Unsupported
            );
            // No applet version at all (HID Crescendo's own GET VERSION
            // extension didn't answer, and its GET PIV PROPERTIES read
            // itself hasn't happened yet either) — nothing to match against.
            assert_eq!(resolve(ext, fp, None, None), FeatureGate::Unverified);
        }
    }

    #[test]
    fn hid_crescendo_generic_has_no_get_metadata_attest_data() {
        // Generic never selects a recognised model at all, so there's no
        // version source for it either way.
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic);
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            assert_eq!(
                resolve(ext, fp, Some(&[3, 0, 3, 6]), None),
                FeatureGate::Unverified
            );
        }
    }

    #[test]
    fn hid_crescendo_c4000_get_metadata_and_attest_known_unsupported_by_documentation() {
        // Assumed from HID's own C4000 documentation, not confirmed on
        // hardware — see `HID_CRESCENDO_C4000_APPLET_VERDICTS`'s doc. Same
        // `KnownUnsupportedSince` at the universal `[]` version as C2300, so
        // no version — documented, observed, or hypothetical-future — is an
        // exception.
        let fp = AppletFingerprint::HidCrescendo(HidCrescendoVariant::C4000);
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            // The documented current version.
            assert_eq!(
                resolve(ext, fp, Some(&[4, 0, 0, 12, 34]), None),
                FeatureGate::Unsupported
            );
            // Anything older than 4.0.0 altogether.
            assert_eq!(
                resolve(ext, fp, Some(&[3, 9, 9, 9, 9]), None),
                FeatureGate::Unsupported
            );
            // A hypothetical future applet revision — unlike an ordinary
            // `KnownUnsupported` row, this doesn't soften to `Unverified`
            // just for being newer than anything documented so far.
            assert_eq!(
                resolve(ext, fp, Some(&[5, 0, 0, 0, 0]), None),
                FeatureGate::Unsupported
            );
            assert_eq!(resolve(ext, fp, None, None), FeatureGate::Unverified);
        }
    }

    #[test]
    fn get_metadata_and_attest_data_does_not_leak_to_other_fingerprints() {
        for ext in [PivExtension::GetMetadata, PivExtension::Attest] {
            assert_eq!(
                resolve(ext, AppletFingerprint::Generic, None, None),
                FeatureGate::Unverified
            );
        }
        // Attest specifically: Token2 carries no row for it (unlike
        // GetMetadata, which has its own genuine `TOKEN2_APPLET_VERDICTS` row
        // now — see `token2_and_thetis_5_112_0_get_metadata_is_supported`
        // below — so it's deliberately not part of this leak check anymore).
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::Token2,
                Some(&[5, 112, 0]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    // --- Token2/Thetis GET METADATA: KnownSupported at 5.112.0 -------------

    #[test]
    fn token2_and_thetis_5_112_0_get_metadata_is_supported() {
        for fp in [AppletFingerprint::Token2, AppletFingerprint::Thetis] {
            assert_eq!(
                resolve(PivExtension::GetMetadata, fp, Some(&[5, 112, 0]), None),
                FeatureGate::Supported
            );
            // No known-unsupported floor recorded below 5.112.0 on either
            // row, so an older reported version resolves `Unverified` rather
            // than inheriting the known-supported verdict backward.
            assert_eq!(
                resolve(PivExtension::GetMetadata, fp, Some(&[5, 111, 0]), None),
                FeatureGate::Unverified
            );
            // A later, untested version is assumed not to have regressed —
            // same forward no-regression rule as every other
            // `Verdict::KnownSupported` row.
            assert_eq!(
                resolve(PivExtension::GetMetadata, fp, Some(&[5, 113, 0]), None),
                FeatureGate::Supported
            );
        }
    }

    // --- YubiKey ATTEST: gained in firmware 4.3 -----------------------------
    // See <https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>.

    #[test]
    fn yubikey_attest_below_4_3_is_unsupported() {
        // Matches the known-unsupported sentinel verdict (version `[]`), which is not
        // the last verdict, so the known-unsupported verdict is authoritative — same shape as
        // `yubikey_below_5_7_is_unsupported` for MOVE KEY/DELETE KEY.
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 2]),
                None
            ),
            FeatureGate::Unsupported
        );
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[3, 4, 0]),
                None,
            ),
            FeatureGate::Unsupported
        );
        // GET METADATA is a separate table with its own `[]` sentinel below
        // its own 5.3 bar — 4.2 is below that bar too, and bracketed by the
        // same sentinel logic, so it resolves the same way here.
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[4, 2]),
                None,
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn yubikey_attest_4_3_and_newer_is_supported() {
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 3]),
                None
            ),
            FeatureGate::Supported
        );
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 3, 7]),
                None,
            ),
            FeatureGate::Supported
        );
        // A later version with no verdict of its own falls to the `[4, 3]`
        // known-supported verdict, assumed not to have regressed.
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[5, 7]),
                None,
            ),
            FeatureGate::Supported
        );
    }

    // --- YubiKey GET METADATA: gained in firmware 5.3 -----------------------
    // See <https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html>.

    #[test]
    fn yubikey_get_metadata_below_5_3_is_unsupported() {
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[5, 2, 0]),
                None,
            ),
            FeatureGate::Unsupported
        );
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[4, 3, 7]),
                None,
            ),
            FeatureGate::Unsupported
        );
        // ATTEST is a separate, unaffected table — 4.3.7 is already at/above
        // its own 4.3 bar.
        assert_eq!(
            resolve(
                PivExtension::Attest,
                AppletFingerprint::YubiKey,
                Some(&[4, 3, 7]),
                None,
            ),
            FeatureGate::Supported
        );
    }

    #[test]
    fn yubikey_get_metadata_5_3_and_newer_is_supported() {
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[5, 3]),
                None,
            ),
            FeatureGate::Supported
        );
        assert_eq!(
            resolve(
                PivExtension::GetMetadata,
                AppletFingerprint::YubiKey,
                Some(&[5, 7]),
                None,
            ),
            FeatureGate::Supported
        );
    }

    #[test]
    fn yubikey_attest_and_get_metadata_without_a_reported_version_are_unverified() {
        for ext in [PivExtension::Attest, PivExtension::GetMetadata] {
            assert_eq!(
                resolve(ext, AppletFingerprint::YubiKey, None, None),
                FeatureGate::Unverified
            );
        }
    }

    // --- GetSlotKeyStatus: falls through to GetMetadata absent its own row ---

    #[test]
    fn get_slot_key_status_without_its_own_row_mirrors_get_metadata_exactly() {
        // No GetSlotKeyStatus row in `YUBIKEY_APPLET_VERDICTS` (across its
        // 5.3 boundary — the version that matters for that table's own
        // YubiKey GetMetadata row), Token2 (which does carry its own
        // GetMetadata row now — see `TOKEN2_APPLET_VERDICTS`'s doc — but still
        // no GetSlotKeyStatus row of its own, which is what the fallthrough
        // actually keys on), or an unrecognized fingerprint — every one of
        // these must resolve identically to `resolve(GetMetadata, ...)`.
        let cases: &[(AppletFingerprint, Option<&[u8]>)] = &[
            (AppletFingerprint::YubiKey, None),
            (AppletFingerprint::YubiKey, Some(&[5, 2])),
            (AppletFingerprint::YubiKey, Some(&[5, 3])),
            (AppletFingerprint::YubiKey, Some(&[6, 0])),
            (AppletFingerprint::Token2, Some(&[5, 112, 0])),
            (AppletFingerprint::Generic, None),
            (AppletFingerprint::Generic, Some(&[1, 0])),
        ];
        for &(fp, version) in cases {
            assert_eq!(
                resolve(PivExtension::GetSlotKeyStatus, fp, version, version),
                resolve(PivExtension::GetMetadata, fp, version, version),
                "{fp:?} at {version:?}"
            );
        }
    }

    #[test]
    fn hid_crescendo_get_slot_key_status_is_known_supported_regardless_of_version() {
        // Unlike every fingerprint in the fallback test above, HID Crescendo
        // has its own row here — `Verdict::KnownSupported` at the universal
        // `[]` version — resolved directly, never falling through to
        // `GetMetadata` (which is `KnownUnsupportedSince` for these same
        // three fingerprints; see `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc). The two
        // extensions must therefore resolve *differently* here, the opposite
        // of the fallback test above.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[99][..]] {
                assert_eq!(
                    resolve(
                        PivExtension::GetSlotKeyStatus,
                        fp,
                        Some(version),
                        Some(version)
                    ),
                    FeatureGate::Supported,
                    "{variant:?} at {version:?}"
                );
            }
            assert_eq!(
                resolve(PivExtension::GetSlotKeyStatus, fp, None, None),
                FeatureGate::Unverified,
                "{variant:?} with no reported version"
            );
        }
        // And explicitly not delegating to `GetMetadata`: C2300/C4000 have
        // their own `KnownUnsupportedSince` row there (see
        // `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s doc), while `Generic` has no GetMetadata row at
        // all (deliberately not extended the way that table's Reset rows
        // are — see that table's own doc) and so resolves `Unverified`
        // — neither matches `GetSlotKeyStatus`'s `Supported` for any of the
        // three, but for two different reasons.
        for (variant, get_metadata_verdict) in [
            (HidCrescendoVariant::C2300, FeatureGate::Unsupported),
            (HidCrescendoVariant::C4000, FeatureGate::Unsupported),
            (HidCrescendoVariant::Generic, FeatureGate::Unverified),
        ] {
            assert_eq!(
                resolve(
                    PivExtension::GetMetadata,
                    AppletFingerprint::HidCrescendo(variant),
                    Some(&[3, 0, 3, 6]),
                    Some(&[3, 0, 3, 6]),
                ),
                get_metadata_verdict,
                "{variant:?}"
            );
        }
    }

    // --- PinManagementAuth: HID Crescendo direct, YubiKey indirect -------

    #[test]
    fn hid_crescendo_pin_management_auth_supported_at_any_version() {
        // The universal `[]` sentinel: HID Crescendo's PIN-unlock is direct
        // (no quirk needed), same shape as `KnownUnsupportedSince` at `[]` on
        // the other tables, just the opposite verdict.
        for variant in [HidCrescendoVariant::C2300, HidCrescendoVariant::C4000] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[1, 2, 3][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::PinManagementAuth, fp, Some(version), None),
                    FeatureGate::Supported
                );
            }
            assert_eq!(
                resolve(PivExtension::PinManagementAuth, fp, None, None),
                FeatureGate::Unverified
            );
        }
        // No quirk on this fingerprint — PIN VERIFY unlocks directly.
        assert!(!resolve_quirks(
            AppletFingerprint::HidCrescendo(HidCrescendoVariant::C2300),
            Some(&[3, 0, 3, 6]),
            None,
        )
        .contains(&PivQuirk::PinManagementAuthProtected9BKey));
    }

    #[test]
    fn yubikey_pin_management_auth_below_3_is_unverified() {
        // No known-unsupported sentinel on this row (unlike MOVE KEY/DELETE
        // KEY's YubiKey row): a version below the first known-supported verdict
        // just has nothing to extend backward from.
        assert_eq!(
            resolve(
                PivExtension::PinManagementAuth,
                AppletFingerprint::YubiKey,
                Some(&[2, 9, 9]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn yubikey_pin_management_auth_3_and_newer_is_supported_with_the_protected_key_quirk() {
        for version in [&[3][..], &[3, 1, 0][..], &[5, 7][..]] {
            assert_eq!(
                resolve(
                    PivExtension::PinManagementAuth,
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None,
                ),
                FeatureGate::Supported
            );
            // Unlike HID Crescendo, YubiKey's PIN unlock is indirect: the
            // quirk marks that the retrieved "management key" is what
            // actually needs to run through the standard 9B round.
            assert!(
                resolve_quirks(AppletFingerprint::YubiKey, Some(version), None)
                    .contains(&PivQuirk::PinManagementAuthProtected9BKey)
            );
        }
    }

    #[test]
    fn yubikey_pin_management_auth_quirk_absent_below_3() {
        assert!(
            !resolve_quirks(AppletFingerprint::YubiKey, Some(&[2, 9, 9]), None)
                .contains(&PivQuirk::PinManagementAuthProtected9BKey)
        );
    }

    // --- PIV RESET: YubiKey supported at any version, HID Crescendo never --

    #[test]
    fn yubikey_reset_supported_at_any_version_with_no_management_auth_quirk() {
        // The universal `[]` sentinel: no known-unsupported floor to clear, unlike
        // MOVE KEY/DELETE KEY's YubiKey row — RESET didn't arrive in a
        // specific later firmware.
        for version in [&[0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::Reset,
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None
                ),
                FeatureGate::Supported
            );
            // `Supported` here means the card accepts `INS 0xFB` at all —
            // *without* `ResetNeedsManagementAuth`, which per that quirk's
            // doc is exactly how a caller reads off the PIN/PUK-blocked
            // convention instead.
            assert!(
                !resolve_quirks(AppletFingerprint::YubiKey, Some(version), None)
                    .contains(&PivQuirk::ResetNeedsManagementAuth)
            );
        }
        assert_eq!(
            resolve(PivExtension::Reset, AppletFingerprint::YubiKey, None, None),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn yubikey_reset_has_no_management_auth_quirk_alongside_the_pin_management_auth_quirk() {
        // Applet version 3+ still carries `PinManagementAuthProtected9BKey`
        // (an unrelated quirk, for a different extension) but no
        // `ResetNeedsManagementAuth` — the two aren't linked.
        let quirks = resolve_quirks(AppletFingerprint::YubiKey, Some(&[5, 7]), None);
        assert!(!quirks.contains(&PivQuirk::ResetNeedsManagementAuth));
        assert!(quirks.contains(&PivQuirk::PinManagementAuthProtected9BKey));
    }

    #[test]
    fn hid_crescendo_reset_unsupported_at_any_version_including_generic() {
        // Same `KnownUnsupportedSince` shape as `HID_CRESCENDO_C2300_APPLET_VERDICTS`'s
        // GetMetadata/Attest HID Crescendo rows, but — unlike those two —
        // also covers `Generic`; see that table's Reset bullets for why.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::Reset, fp, Some(version), None),
                    FeatureGate::Unsupported
                );
            }
            // The not-yet-implemented replacement mechanism's quirk is
            // already in place, ready for the workaround to key off of.
            assert!(
                resolve_quirks(fp, Some(&[0]), None).contains(&PivQuirk::ResetNeedsManagementAuth)
            );
        }
    }

    #[test]
    fn reset_data_does_not_leak_to_other_fingerprints() {
        assert_eq!(
            resolve(PivExtension::Reset, AppletFingerprint::Generic, None, None),
            FeatureGate::Unverified
        );
        // Thetis has a `KnownUnsupported` row at 5.112.0 for MoveKey/DeleteKey
        // for MoveKey/DeleteKey but no Reset row at all — proves that
        // data doesn't leak across extensions.
        // (Token2 no longer demonstrates this: it now has its own genuine
        // `KnownSupported` row here at the same version — see
        // `token2_5_112_0_reset_is_supported` instead.)
        assert_eq!(
            resolve(
                PivExtension::Reset,
                AppletFingerprint::Thetis,
                Some(&[5, 112, 0]),
                None,
            ),
            FeatureGate::Unverified
        );
        assert!(
            !resolve_quirks(AppletFingerprint::Thetis, Some(&[5, 112, 0]), None)
                .contains(&PivQuirk::ResetNeedsManagementAuth)
        );
    }

    #[test]
    fn token2_5_112_0_reset_is_supported() {
        // Hardware-observed known-supported verdict, pinned to exactly the
        // version keyroost has evidence for — see the Token2 bullet in
        // `TOKEN2_APPLET_VERDICTS`'s doc. As with the YubiKey row, a version above
        // 5.112.0 still resolves `Supported` only via `KnownSupported`'s
        // ordinary forward no-regression assumption, not because the row
        // itself covers every version.
        for version in [&[5, 112, 0][..], &[5, 113, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::Reset,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Supported,
                "{version:?}"
            );
        }
        // No known-unsupported floor recorded below 5.112.0 (unlike
        // `TOKEN2_APPLET_VERDICTS`'s MoveKey/DeleteKey rows, which
        // are `KnownUnsupported` at this same version and so extend
        // backward): an older reported version falls off this row entirely
        // and resolves `Unverified`, not `Supported` or `Unsupported`.
        for version in [&[5, 111, 0][..], &[0][..]] {
            assert_eq!(
                resolve(
                    PivExtension::Reset,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Unverified,
                "{version:?}"
            );
        }
        assert_eq!(
            resolve(PivExtension::Reset, AppletFingerprint::Token2, None, None),
            FeatureGate::Unverified
        );
        // No `ResetNeedsManagementAuth` entry on
        // `TOKEN2_APPLET_QUIRKS` — RESET doesn't need an authenticated
        // management-key session here. Unlike YubiKey, that absence doesn't
        // mean it falls back to the PIN/PUK-burn convention either: hardware
        // testing showed a live 5.112.0 unit accepts RESET unconditionally.
        // See `PivQuirk::ResetNeedsManagementAuth`'s own doc.
        assert!(
            !resolve_quirks(AppletFingerprint::Token2, Some(&[5, 112, 0]), None)
                .contains(&PivQuirk::ResetNeedsManagementAuth)
        );
    }

    // --- PIV RESET_GLOBAL: HID Crescendo C2300/C4000 only, not Generic ---

    #[test]
    fn hid_crescendo_c2300_c4000_reset_global_supported_at_any_version() {
        for variant in [HidCrescendoVariant::C2300, HidCrescendoVariant::C4000] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::ResetGlobal, fp, Some(version), None),
                    FeatureGate::Supported
                );
            }
            assert_eq!(
                resolve(PivExtension::ResetGlobal, fp, None, None),
                FeatureGate::Unverified
            );
        }
    }

    #[test]
    fn hid_crescendo_generic_has_no_reset_global_data() {
        // Unlike `PivExtension::Reset`'s known-unsupported row, `ResetGlobal`'s
        // known-supported claim deliberately isn't extended to `Generic` — see
        // `GENERIC_APPLET_VERDICTS`'s doc for why.
        assert_eq!(
            resolve(
                PivExtension::ResetGlobal,
                AppletFingerprint::HidCrescendo(HidCrescendoVariant::Generic),
                Some(&[3, 0, 3, 6]),
                None,
            ),
            FeatureGate::Unverified
        );
    }

    /// Every fingerprint that isn't `HidCrescendo` carries its own explicit
    /// `Verdict::KnownUnsupportedSince` row (see `RESET_GLOBAL_VERDICTS`'s
    /// doc for why an explicit "no" beats leaving these absent) -- a flat
    /// `Unsupported` at any reported version, not the `Unverified` an absent
    /// row would give. Covers every `AppletFingerprint` variant currently
    /// defined outside `HidCrescendo`, one representative version each plus
    /// a second to prove it's not just the exact-match version that resolves
    /// this way.
    #[test]
    fn reset_global_is_known_unsupported_for_every_non_hid_crescendo_fingerprint() {
        let non_hid_crescendo = [
            AppletFingerprint::Generic,
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::Generic),
            AppletFingerprint::ArekinathPivApplet(ArekinathVariant::SwissbitIShield1),
            AppletFingerprint::AuthentrendATKey,
            AppletFingerprint::Feitian,
            AppletFingerprint::IdPrime,
            AppletFingerprint::Trussed(TrussedVariant::NitroKey),
            AppletFingerprint::OpenFips201(OpenFips201Variant::Generic),
            AppletFingerprint::OpenFips201(OpenFips201Variant::SwissbitIShield2),
            AppletFingerprint::Thetis,
            AppletFingerprint::Token2,
            AppletFingerprint::UTrust,
            AppletFingerprint::YubiKey,
        ];
        for fp in non_hid_crescendo {
            for version in [&[0][..], &[9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::ResetGlobal, fp, Some(version), None),
                    FeatureGate::Unsupported,
                    "{fp:?} at {version:?}"
                );
            }
            // No reported version at all still can't match any row --
            // `resolve_in` returns `Unverified` before ever consulting the
            // table, same as any other extension.
            assert_eq!(
                resolve(PivExtension::ResetGlobal, fp, None, None),
                FeatureGate::Unverified,
                "{fp:?} with no reported version"
            );
        }
    }

    // --- PIV SET_PIN_PUK_RETRIES: YubiKey always, Token2 at 5.112.0, HID
    // --- Crescendo never ---------------------------------------------------

    #[test]
    fn yubikey_set_pin_puk_retries_always_supported() {
        // No known-unsupported floor, same shape as `RESET_VERDICTS`'s YubiKey
        // row — SET PIN RETRIES didn't arrive in a specific later firmware,
        // unlike MOVE KEY/DELETE KEY's YubiKey row.
        for version in [&[0][..], &[1, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SetPinPukRetries,
                    AppletFingerprint::YubiKey,
                    Some(version),
                    None
                ),
                FeatureGate::Supported
            );
        }
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::YubiKey,
                None,
                None
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn token2_5_112_0_set_pin_puk_retries_is_supported() {
        // Hardware-observed known-supported verdict, pinned to exactly the
        // version keyroost has evidence for — see the Token2 bullet in
        // `SET_PIN_PUK_RETRIES_VERDICTS`'s doc. Unlike the YubiKey row above,
        // there's no universal `[]` verdict here, so a version above 5.112.0
        // still resolves `Supported` only via `KnownSupported`'s ordinary
        // forward no-regression assumption, not because the row itself
        // covers every version.
        for version in [&[5, 112, 0][..], &[5, 113, 0][..], &[9, 9, 9][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SetPinPukRetries,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Supported,
                "{version:?}"
            );
        }
        // No known-unsupported floor recorded below 5.112.0 (unlike
        // `MOVE_KEY_VERDICTS`'s/`DELETE_KEY_VERDICTS`'s Token2 rows, which
        // are `KnownUnsupported` at this same version and so extend
        // backward): an older reported version falls off this row entirely
        // and resolves `Unverified`, not `Supported` or `Unsupported`.
        for version in [&[5, 111, 0][..], &[0][..]] {
            assert_eq!(
                resolve(
                    PivExtension::SetPinPukRetries,
                    AppletFingerprint::Token2,
                    Some(version),
                    None
                ),
                FeatureGate::Unverified,
                "{version:?}"
            );
        }
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::Token2,
                None,
                None
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn hid_crescendo_set_pin_puk_retries_unsupported_at_any_version_including_generic() {
        // Same `KnownUnsupportedSince` shape as `RESET_VERDICTS`'s HID
        // Crescendo rows, and likewise covers `Generic` alongside the two
        // named models — see `SET_PIN_PUK_RETRIES_VERDICTS`'s doc. C4000 in
        // particular is blocked for lack of a documented APDU, not lack of
        // any HID mechanism — see that row's comment.
        for variant in [
            HidCrescendoVariant::C2300,
            HidCrescendoVariant::C4000,
            HidCrescendoVariant::Generic,
        ] {
            let fp = AppletFingerprint::HidCrescendo(variant);
            for version in [&[0][..], &[3, 0, 3, 6][..], &[9, 9, 9, 9][..]] {
                assert_eq!(
                    resolve(PivExtension::SetPinPukRetries, fp, Some(version), None),
                    FeatureGate::Unsupported,
                    "{fp:?} at {version:?}"
                );
            }
            assert_eq!(
                resolve(PivExtension::SetPinPukRetries, fp, None, None),
                FeatureGate::Unverified,
                "{fp:?} with no reported version"
            );
        }
    }

    #[test]
    fn set_pin_puk_retries_data_does_not_leak_to_other_fingerprints() {
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::Generic,
                None,
                None
            ),
            FeatureGate::Unverified
        );
        // Thetis has a `KnownUnsupported` row at 5.112.0 in
        // `MOVE_KEY_VERDICTS`/`DELETE_KEY_VERDICTS` but no row at all in
        // `SET_PIN_PUK_RETRIES_VERDICTS` — proves that data doesn't leak
        // across tables. (Token2 no longer demonstrates this: it now has its
        // own genuine `KnownSupported` row here at the same version — see
        // `token2_5_112_0_set_pin_puk_retries_is_supported` instead.)
        assert_eq!(
            resolve(
                PivExtension::SetPinPukRetries,
                AppletFingerprint::Thetis,
                Some(&[5, 112, 0]),
                None,
            ),
            FeatureGate::Unverified
        );
    }
}
