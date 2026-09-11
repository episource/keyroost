//! Per-fingerprint white/blacklist for the non-standard PIV commands keyroost
//! exposes.
//!
//! A handful of management operations in this crate are vendor extensions, not
//! SP 800-73-4: Yubico's MOVE KEY and DELETE KEY, which landed in YubiKey
//! firmware 5.7. "Speaks PIV" says nothing about whether a given applet
//! implements them, and the answer can differ between firmware versions of the
//! same product. This module encodes what keyroost has actually observed,
//! keyed by [`AppletFingerprint`], as a **combined white/blacklist**: for each
//! fingerprint it knows about, a list of per-version verdicts each either
//! [`Verdict::Whitelisted`] ("extension known to be supported at this version")
//! or [`Verdict::Blacklisted`] ("extension known to be unsupported at this
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
//! combination rule). Per axis, it is deliberately conservative about
//! *disabling*: a control is only ever [`FeatureGate::Unsupported`] on that
//! axis when the table has a blacklist verdict that actually covers the
//! reported version. Anything less certain — no verdicts for the fingerprint
//! at all, none at or below the reported version, no reported version, or only
//! a blacklist verdict old enough that a later firmware might have added the
//! extension — resolves to [`FeatureGate::Unverified`] on that axis, which
//! keeps the control usable unless the other axis disagrees.
//!
//! The same per-version rows also carry [`PivQuirk`]s — observed behavioral
//! wrinkles that need a workaround rather than gating a control. Quirks are
//! resolved separately by [`resolve_quirks`], with simpler semantics than
//! [`resolve`]: no whitelist/blacklist, just "take the current entry on each
//! axis and merge whatever quirks it lists."

use std::collections::BTreeSet;

use crate::fingerprint::AppletFingerprint;

/// One of the non-standard, vendor-extension PIV commands keyroost exposes —
/// nothing in SP 800-73-4 defines it, so support varies by applet and is
/// gated by device fingerprint through [`resolve`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivExtension {
    /// Yubico MOVE KEY — relocate a slot's private key into another slot.
    MoveKey,
    /// Yubico DELETE KEY — erase a slot's private key in place.
    DeleteKey,
}

impl PivExtension {
    /// This extension's white/blacklist keyed by the PIV **applet's own**
    /// version (Yubico's `GET VERSION` extension reply): one
    /// [`FingerprintVerdicts`] row per fingerprint keyroost has data for on
    /// this axis. A fingerprint absent from the slice means "no data" and
    /// [`resolve`] treats this axis as [`FeatureGate::Unverified`].
    #[must_use]
    fn applet_verdicts(self) -> &'static [FingerprintVerdicts] {
        match self {
            // MOVE KEY and DELETE KEY shipped together in YubiKey firmware
            // 5.7: unsupported at every earlier version, supported from 5.7 on.
            PivExtension::MoveKey | PivExtension::DeleteKey => YUBICO_5_7_KEY_OPS,
        }
    }

    /// This extension's white/blacklist keyed by the device's **firmware**
    /// version, same shape and lookup rules as [`Self::applet_verdicts`] but a
    /// separate axis — a fingerprint can have data on one and not the other.
    /// No fingerprint has firmware-version data yet, so every extension
    /// resolves this axis to [`FeatureGate::Unverified`] today.
    #[must_use]
    fn firmware_verdicts(self) -> &'static [FingerprintVerdicts] {
        match self {
            PivExtension::MoveKey | PivExtension::DeleteKey => &[],
        }
    }

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
    /// The algorithm byte returned by the Yubico extension APDU GET METADATA
    /// (`INS 0xF7`) is invalid/unreliable on this device and must be
    /// ignored.
    InsF7MetadataAlgorithmInvalid,
}

/// The white/blacklist shared by [`PivExtension::MoveKey`] and
/// [`PivExtension::DeleteKey`]: on a YubiKey the operation is unsupported before
/// firmware 5.7 and supported from 5.7 onward, and keyroost has no data for
/// any other applet. The empty-slice version on the blacklist verdict is a
/// "from the very first version" sentinel — it orders below every real
/// version (`[] < [5, 7]`), so that verdict is the one that applies to
/// anything older than 5.7.
const YUBICO_5_7_KEY_OPS: &[FingerprintVerdicts] = &[FingerprintVerdicts {
    fingerprint: AppletFingerprint::YubiKey,
    verdicts: &[
        VersionVerdict {
            version: &[],
            verdict: Verdict::Blacklisted,
        },
        VersionVerdict {
            version: &[5, 7],
            verdict: Verdict::Whitelisted,
        },
    ],
}];

/// One fingerprint's row in an extension's white/blacklist.
struct FingerprintVerdicts {
    fingerprint: AppletFingerprint,
    /// This fingerprint's per-version verdicts, **ascending by
    /// [`VersionVerdict::version`]** and non-empty.
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

/// One recorded white/blacklist verdict, carried by a [`VersionVerdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Extension known to be supported at this version (and, by the
    /// no-regression assumption in [`resolve`], at every later one until a
    /// contrary verdict).
    Whitelisted,
    /// Extension known to be unsupported at this version.
    Blacklisted,
}

/// The UI-facing resolution of a [`PivExtension`] against a live applet,
/// produced by [`resolve`]. Not `#[non_exhaustive]`: it is a closed
/// three-way outcome and every caller is expected to render all three
/// (enable / enable-and-flag / dim) rather than fall through a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureGate {
    /// Enable the control, no warning: the extension is whitelisted at the
    /// reported version, or at an earlier one and assumed not to have
    /// regressed.
    Supported,
    /// Enable the control, but flag it: keyroost has no white/blacklist for
    /// this fingerprint, none at or below the reported version, no reported
    /// version to match, or only a blacklist verdict old enough that a later
    /// firmware may have added the extension. See [`Self::UNVERIFIED_SUFFIX`].
    Unverified,
    /// Disable the control (dimmed): a blacklist verdict covers the reported
    /// version, so the extension is known to be unsupported here.
    Unsupported,
}

impl FeatureGate {
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unverified`](Self::Unverified): the device isn't on the
    /// white/blacklist, so support can't be confirmed either way.
    pub const UNVERIFIED_SUFFIX: &'static str =
        "This device is unverified; the operation may fail.";
    /// Sentence that follows [`PivExtension::requirement`] when a control is
    /// gated [`Unsupported`](Self::Unsupported): a blacklist verdict covers
    /// this device's version.
    pub const INCOMPATIBLE_SUFFIX: &'static str = "This device is known to be incompatible.";
}

/// Resolve `extension` for an applet fingerprinted as `fingerprint`, reporting
/// `applet_version` (the PIV applet's own version bytes) and/or
/// `firmware_version` (the device firmware's version bytes) — either or both
/// `None` when the card never reported that one.
///
/// `applet_version` is queried against [`PivExtension::applet_verdicts`] and
/// `firmware_version` against [`PivExtension::firmware_verdicts`], **with
/// identical per-axis lookup semantics**:
///
/// 1. The version is `None` → that axis is [`FeatureGate::Unverified`]
///    (nothing to version-match).
/// 2. No white/blacklist row for `fingerprint` on that axis →
///    [`FeatureGate::Unverified`] (support unknown; don't block).
/// 3. A row exists: take the verdict with the greatest version `<=` the
///    reported version. If there is none (the reported version is older than
///    every verdict) → [`FeatureGate::Unverified`]. Otherwise:
///    * whitelisted → [`FeatureGate::Supported`] (covers both an exact-version
///      match and an earlier whitelist assumed not to have regressed);
///    * blacklisted, verdict version **equals** the reported version →
///      [`FeatureGate::Unsupported`];
///    * blacklisted, verdict version **below** the reported version, and it is
///      the last (highest) verdict in the row → [`FeatureGate::Unverified`]:
///      the blacklist may predate a firmware that added the extension;
///    * blacklisted, verdict version **below** the reported version, but a
///      later verdict exists (for a version above this one's) → the row's
///      blacklist knowledge brackets this version, so it is treated as
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
#[must_use]
pub fn resolve(
    extension: PivExtension,
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> FeatureGate {
    let applet_gate = resolve_in(extension.applet_verdicts(), fingerprint, applet_version);
    let firmware_gate = resolve_in(extension.firmware_verdicts(), fingerprint, firmware_version);
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

/// [`resolve`] against an explicit set of white/blacklist rows, so a test can
/// supply its own without wiring one into the const tables.
fn resolve_in(
    rows: &[FingerprintVerdicts],
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
) -> FeatureGate {
    let Some(version) = applet_version else {
        return FeatureGate::Unverified;
    };
    let Some(row) = rows.iter().find(|row| row.fingerprint == fingerprint) else {
        return FeatureGate::Unverified;
    };
    let Some(idx) = row.verdicts.iter().rposition(|v| v.version <= version) else {
        return FeatureGate::Unverified;
    };
    let chosen = &row.verdicts[idx];
    match chosen.verdict {
        // Known supported at or below the reported version — and assumed not
        // to have regressed in any newer version we have no verdict for.
        Verdict::Whitelisted => FeatureGate::Supported,
        // Blacklist verdict for exactly this version: a direct observation
        // that this build lacks the extension. Nothing softens that.
        Verdict::Blacklisted if chosen.version == version => FeatureGate::Unsupported,
        // Blacklist verdict from an *older* version with nothing newer on
        // record: the extension may have been added in a firmware we haven't
        // observed, so warn rather than block.
        Verdict::Blacklisted if idx + 1 == row.verdicts.len() => FeatureGate::Unverified,
        // Blacklist verdict from an older version, but a later verdict exists
        // (for a version above this applet's): our blacklist knowledge
        // brackets this version, so treat it as authoritative and block.
        Verdict::Blacklisted => FeatureGate::Unsupported,
    }
}

/// One fingerprint's row in a [`PivQuirk`] table — the quirks counterpart to
/// [`FingerprintVerdicts`], but deliberately a separate type: a quirk row has
/// no whitelist/blacklist [`Verdict`] to carry, only a list of quirks active
/// from each entry's version onward, so reusing [`VersionVerdict`] would
/// leave a `verdict` field with no meaning on this axis.
struct FingerprintQuirks {
    fingerprint: AppletFingerprint,
    /// This fingerprint's per-version quirks, **ascending by
    /// [`VersionQuirks::version`]** and non-empty.
    quirks: &'static [VersionQuirks],
}

/// "At [`Self::version`] (and, until a later entry, above it) these quirks
/// are active." Same version-ordering convention as [`VersionVerdict`], but
/// purely additive: there's no whitelisted/blacklisted state, so a quirk
/// entry can never suppress a quirk an earlier entry already reported.
struct VersionQuirks {
    version: &'static [u8],
    quirks: &'static [PivQuirk],
}

/// [`PivQuirk`] table keyed by the PIV applet's own version — same row shape
/// as [`PivExtension::applet_verdicts`], but not scoped to any one
/// extension: every fingerprint's known version-gated quirks live directly
/// in this one table rather than being duplicated per extension. Empty
/// today — no fingerprint has recorded applet-version quirk data yet, so
/// [`resolve_quirks`] always resolves this axis to an empty set until an
/// entry is added.
const QUIRK_APPLET_TABLE: &[FingerprintQuirks] = &[];

/// [`PivQuirk`] table keyed by the device's firmware version, same shape and
/// caveats as [`QUIRK_APPLET_TABLE`] but the firmware axis.
const QUIRK_FIRMWARE_TABLE: &[FingerprintQuirks] = &[];

/// The row entry in `rows` for `fingerprint` with the greatest
/// [`VersionQuirks::version`] `<=` `version`, if any — the "current" quirks
/// entry for that version, ignoring anything with a higher version on
/// record. Same lookup rule as step 3 of [`resolve_in`], but there's no
/// whitelist/blacklist reasoning to apply once the entry is found: quirks
/// are taken as-is.
fn latest_quirks<'a>(
    rows: &'a [FingerprintQuirks],
    fingerprint: AppletFingerprint,
    version: &[u8],
) -> Option<&'a VersionQuirks> {
    let row = rows.iter().find(|row| row.fingerprint == fingerprint)?;
    let idx = row.quirks.iter().rposition(|v| v.version <= version)?;
    Some(&row.quirks[idx])
}

/// Resolve the set of [`PivQuirk`]s active for an applet fingerprinted as
/// `fingerprint`, reporting `applet_version` and/or `firmware_version` —
/// either or both `None` when the card never reported that one:
///
/// 1. If `applet_version` is available, take the [`QUIRK_APPLET_TABLE`]
///    entry for `fingerprint` with the highest version `<=` `applet_version`
///    (if any).
/// 2. If `firmware_version` is available, take the [`QUIRK_FIRMWARE_TABLE`]
///    entry for `fingerprint` with the highest version `<=`
///    `firmware_version` (if any).
/// 3. Merge the [`VersionQuirks::quirks`] from whichever of (1)/(2) matched
///    into a single set.
///
/// Unlike [`resolve`], there's no whitelist/blacklist reasoning here: each
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
        QUIRK_APPLET_TABLE,
        QUIRK_FIRMWARE_TABLE,
        fingerprint,
        applet_version,
        firmware_version,
    )
}

/// [`resolve_quirks`] against explicit applet/firmware quirk tables, so a
/// test can supply its own without wiring one into the const tables — same
/// role [`resolve_in`] plays for [`resolve`].
fn resolve_quirks_in(
    applet_rows: &[FingerprintQuirks],
    firmware_rows: &[FingerprintQuirks],
    fingerprint: AppletFingerprint,
    applet_version: Option<&[u8]>,
    firmware_version: Option<&[u8]>,
) -> BTreeSet<PivQuirk> {
    let mut quirks = BTreeSet::new();
    if let Some(version) = applet_version {
        if let Some(entry) = latest_quirks(applet_rows, fingerprint, version) {
            quirks.extend(entry.quirks.iter().copied());
        }
    }
    if let Some(version) = firmware_version {
        if let Some(entry) = latest_quirks(firmware_rows, fingerprint, version) {
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
        let move_req = PivExtension::MoveKey.requirement();
        let del_req = PivExtension::DeleteKey.requirement();
        assert_ne!(move_req, del_req);
        for req in [move_req, del_req] {
            // Ends a sentence, so "<req> <suffix>" reads as two.
            assert!(req.ends_with('.'), "{req:?}");
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
            // Matches the blacklist sentinel verdict (version `[]`), which is
            // not the last verdict, so the blacklist is authoritative.
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
            // whitelist, assumed not to have regressed.
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
            assert_eq!(
                resolve(
                    PivExtension::MoveKey,
                    AppletFingerprint::Token2,
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
        let rows = [FingerprintVerdicts {
            fingerprint: AppletFingerprint::Generic,
            verdicts,
        }];
        resolve_in(&rows, AppletFingerprint::Generic, version)
    }

    #[test]
    fn applet_older_than_every_verdict_is_unverified() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::Whitelisted,
                }],
                Some(&[4, 9]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn exact_version_blacklist_match_is_unsupported() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::Blacklisted,
                }],
                Some(&[5, 7]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn trailing_stale_blacklist_is_unverified() {
        // Only a blacklist, from a version below the applet's, and it is the
        // last verdict — the extension might have been added since.
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 0],
                    verdict: Verdict::Blacklisted,
                }],
                Some(&[5, 4]),
            ),
            FeatureGate::Unverified
        );
    }

    #[test]
    fn bracketed_blacklist_stays_authoritative() {
        // A blacklist below the applet's version, with a later verdict above
        // it: keyroost's blacklist knowledge brackets the applet version.
        assert_eq!(
            gate(
                &[
                    VersionVerdict {
                        version: &[5, 0],
                        verdict: Verdict::Blacklisted,
                    },
                    VersionVerdict {
                        version: &[6, 0],
                        verdict: Verdict::Whitelisted,
                    },
                ],
                Some(&[5, 4]),
            ),
            FeatureGate::Unsupported
        );
    }

    #[test]
    fn earlier_whitelist_is_assumed_not_to_regress() {
        assert_eq!(
            gate(
                &[VersionVerdict {
                    version: &[5, 7],
                    verdict: Verdict::Whitelisted,
                }],
                Some(&[9, 1, 2]),
            ),
            FeatureGate::Supported
        );
    }

    // --- resolve_quirks(): the separate, non-gating quirks axis ----------

    fn quirks(
        applet_entries: &'static [VersionQuirks],
        firmware_entries: &'static [VersionQuirks],
        applet_version: Option<&[u8]>,
        firmware_version: Option<&[u8]>,
    ) -> BTreeSet<PivQuirk> {
        let applet_rows = [FingerprintQuirks {
            fingerprint: AppletFingerprint::Generic,
            quirks: applet_entries,
        }];
        let firmware_rows = [FingerprintQuirks {
            fingerprint: AppletFingerprint::Generic,
            quirks: firmware_entries,
        }];
        resolve_quirks_in(
            &applet_rows,
            &firmware_rows,
            AppletFingerprint::Generic,
            applet_version,
            firmware_version,
        )
    }

    #[test]
    fn no_data_on_either_axis_resolves_to_no_quirks() {
        assert_eq!(
            resolve_quirks(AppletFingerprint::YubiKey, Some(&[5, 7]), Some(&[5, 7])),
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
        assert_eq!(
            resolve_quirks(AppletFingerprint::Generic, Some(&[1, 0]), Some(&[1, 0])),
            BTreeSet::new()
        );
    }
}
