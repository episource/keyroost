//! IAS Classic/ECC smart-card byte layer (Thales eToken 5300 and similar).
//!
//! A pure, I/O-free APDU builder + parser layer for IAS Classic/ECC smart
//! cards, the same shape as `keyroost-piv`/`keyroost-oath`/`keyroost-openpgp`:
//! it turns intentions into APDU byte vectors and response bytes into typed
//! values, and performs **no card I/O** (that lives in `keyroost-transport`'s
//! `IasSession`).
//!
//! # This crate was built without a reference specification
//!
//! Unlike this workspace's PIV support (built directly from the public NIST
//! SP 800-73-4 document), no ANSSI IAS-ECC referential or Thales/IDPrime
//! command reference was available while writing this crate, and no IAS
//! hardware was available to trace against. Every byte value below is one of:
//!
//! - **`[HIGH]`** — a genuinely standard ISO 7816-4 base instruction, or a
//!   convention already confirmed working in this workspace against real
//!   hardware (IAS's PERFORM SECURITY OPERATION framing is byte-identical to
//!   `keyroost-openpgp`'s, which is tested against real OpenPGP cards).
//! - **`[GUESS]`** — a specific, reasoned placeholder that is plausible but
//!   unconfirmed, and likely wrong in some detail.
//! - **`[UNKNOWN]`** — no defensible default exists (e.g. the admin-key
//!   crypto); the code isolates these into single functions/tables so a
//!   correction, once a real device is traced, is a point-edit, not a
//!   rewrite. See `CLAUDE.md`'s "Known soft spots" for the running list.
//!
//! # Reuse of `keyroost-piv`
//!
//! This crate takes a path dependency on `keyroost-piv` for its `x509`,
//! `x509_parse`, and `spki` modules only — pure DER CSR/certificate/SPKI
//! code that is algorithm-shape-driven (RSA modulus/exponent sizes, EC
//! curves), not PIV-protocol-driven. It is never used here for PIV protocol
//! bytes, and [`KeyAlg`] is a deliberately separate type from
//! `keyroost_piv::KeyAlg` (see its doc comment for why) — [`KeyAlg::to_piv_alg`]
//! is the one narrow bridge between the two, used only at DER-construction
//! call sites in `keyroost-transport`.

#![forbid(unsafe_code)]

use keyroost_proto::apdu::{build_apdu, build_apdu_ext, build_apdu_get, chain_apdu, push_tlv};
use zeroize::Zeroizing;

/// A DER-decoded public key: RSA modulus/exponent or an EC point. Identical
/// in shape to `keyroost_piv::PublicKey` (this is just DER-relevant key
/// material, not protocol-specific), so this crate reuses that type directly
/// rather than defining a byte-identical duplicate.
pub use keyroost_piv::PublicKey;

// ---------------------------------------------------------------------------
// AID, status words, reference bytes
// ---------------------------------------------------------------------------

/// Best-effort candidate AIDs for IAS-ECC/IAS-Classic-family applets, tried
/// in order by the transport layer's `open()`. The transport layer also
/// accepts a `--aid`/env override tried *first* — use it the moment a trace
/// shows an AID not already in this list, rather than editing it.
///
/// The first entry is no longer a guess: an ATR captured from a real SafeNet
/// eToken 5300 (`3b ff 96 00 00 81 31 fe 43 80 31 80 65 b0 84 56 51 10 12 01
/// 78 82 90 00 6a`) matches — modulo the historical-byte tail OpenSC's own
/// ATR-matching masks already treat as don't-care — the ATR table entry
/// OpenSC's `card-idprime.c` uses to identify a **Gemalto/Thales IDPrime**
/// card (the `SC_CARD_TYPE_IDPRIME_930_PLUS`/`_940` family, "eToken 5110+
/// FIPS" in that table's own label). That driver's own AID is what's listed
/// first below (`select()`'s bytes are used exactly as given — SELECT by
/// full DF name — since `card-idprime.c` never truncates it, using this
/// single 11-byte value unmodified across all five ATR-distinguished chip
/// variants it supports). IDPrime is Thales's own applet on this exact chip
/// family — publicly branded "IAS Classic" in Gemalto/Thales's own FIPS
/// documentation for the IDPrime MD/930/3930 line — not a separately-issued
/// IAS-Classic/ECC deployment, but close enough in ISO 7816-8 command
/// vocabulary (confirmed by a real PIN-VERIFY trace and PIN-padding fix for
/// this exact chip family, see [`PIN_REF_USER`]) that this crate's
/// IAS-Classic-shaped builders are still the closest starting point, not a
/// wrong turn.
///
/// The second entry is a **partial-name fallback**, not a distinct guess:
/// ISO 7816-4 SELECT (`P1=0x04`, "select by DF name") matches on a
/// right-truncated name as long as it unambiguously identifies one
/// application on the card — this is the exact mechanism
/// [`keyroost_piv::AID`] already relies on for PIV in this workspace
/// (PIV's 11-byte AID is truncated to its 5-byte RID/PIX prefix
/// `A0 00 00 03 08`, and that's the one actually sent over the wire,
/// hardware-verified earlier in this project). Applying the same idea here:
/// if the real card's full AID differs from the IDPrime driver's in a
/// trailing byte (a per-product/version suffix, a real pattern in other
/// vendor AID schemes), a shorter prefix still selects it. Truncated by
/// exactly one byte (dropping the trailing `0x62`) rather than all the way
/// to the bare 5-byte Gemalto RID `A0 00 00 00 18` — that RID is shared
/// across many unrelated Gemalto/Thales applets (MD, PIV-compatible,
/// OpenPGP-like), so an automatic RID-only try risks selecting the wrong
/// application on a multi-applet card, or failing ambiguity checks outright.
/// `--aid a000000018` remains available as a manual, deliberate escape
/// hatch if a trace ever calls for going that short.
pub const CANDIDATE_AIDS: &[&[u8]] = &[
    // Gemalto/Thales IDPrime applet AID, byte-for-byte from OpenSC's
    // card-idprime.c (`idprime_path`) — the exact driver for this chip
    // family, per the ATR match this constant's own doc comment describes.
    // [HIGH] confidence this is the real AID for the eToken 5300.
    &[
        0xA0, 0x00, 0x00, 0x00, 0x18, 0x80, 0x00, 0x00, 0x00, 0x06, 0x62,
    ],
    // One-byte-truncated prefix of the AID above, relying on ISO 7816-4
    // partial-DF-name SELECT (the same mechanism keyroost-piv uses for PIV's
    // own AID). [GUESS] that this specific truncation point is where a real
    // per-product suffix would start; see this constant's own doc comment.
    &[0xA0, 0x00, 0x00, 0x00, 0x18, 0x80, 0x00, 0x00, 0x00, 0x06],
    // Uruguay's national eID ("Cédula de Identidad") AID, byte-for-byte from
    // OpenSC's card-cedulauy.c driver — a different real, deployed
    // IAS-Classic-family card (not IDPrime). Shares the same Gemalto RID
    // (`A0 00 00 00 18`) as the IDPrime AID above, differing only in the
    // PIX suffix — issuers of the same card family register their own AIDs.
    &[
        0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00,
    ],
    // A commonly-cited ANSSI IAS-ECC-profile applet AID. GUESS.
    &[
        0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01,
        0x00,
    ],
    // A generic "IAS" RID prefix some issuers register under. GUESS, likely wrong.
    &[0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00],
];

/// Status word: success.
pub const SW_OK: u16 = 0x9000;
/// First byte of a `61xx` "more data available" status word.
pub const SW_MORE_DATA: u8 = 0x61;
/// File/application/object not found.
pub const SW_NOT_FOUND: u16 = 0x6A82;
/// Security status not satisfied (a write needed an auth/PIN that wasn't done).
pub const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
/// Authentication method blocked (PIN/PUK/admin key exhausted).
pub const SW_AUTH_BLOCKED: u16 = 0x6983;
/// Reference data (key/PIN reference) not found.
pub const SW_REFERENCE_NOT_FOUND: u16 = 0x6A88;
/// Instruction code not supported by this card/applet.
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

/// VERIFY/CHANGE REFERENCE DATA/RESET RETRY COUNTER reference (P2) for the
/// user PIN. `[HIGH]` — confirmed by a real APDU trace from a SafeNet eToken
/// 5100/5110 SC (OpenSC issue #3488: `00 20 00 11 ...`), the same Gemalto
/// IDPrime chip family as the eToken 5300 (confirmed by ATR match — see
/// `CANDIDATE_AIDS`'s doc comment).
pub const PIN_REF_USER: u8 = 0x11;
/// Key reference (P2 of EXTERNAL AUTHENTICATE / VERIFY, if the card treats
/// the admin/SO secret as VERIFY-able) for the admin/SO key. **`[GUESS]`**.
pub const ADMIN_KEY_REF: u8 = 0x02;

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

/// IAS Classic/ECC instruction bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Instruction {
    /// SELECT — ISO 7816-4 base instruction. `[HIGH]`
    Select = 0xA4,
    /// VERIFY — present the PIN, or query its retry counter with an empty
    /// body. ISO 7816-4 base instruction. `[HIGH]`
    Verify = 0x20,
    /// CHANGE REFERENCE DATA — change the PIN. ISO 7816-4 base instruction.
    /// `[HIGH]`
    ChangeReferenceData = 0x24,
    /// RESET RETRY COUNTER — unblock the PIN via an unblock code. Ubiquitous
    /// across PIV/OpenPGP/GlobalPlatform-style profiles at this byte value
    /// (matches what this workspace's own PIV/OpenPGP layers use for the
    /// same concept). `[HIGH-by-convention]`
    ResetRetryCounter = 0x2C,
    /// GET CHALLENGE — the card issues a nonce for EXTERNAL AUTHENTICATE.
    /// ISO 7816-4 base instruction. `[HIGH]` (the *use* of it for admin-key
    /// auth, and everything about the crypto underneath, is `[UNKNOWN]` —
    /// see `keyroost-transport::ias::admin_crypt`).
    GetChallenge = 0x84,
    /// EXTERNAL AUTHENTICATE — host proves it holds the admin/SO key by
    /// answering the GET CHALLENGE nonce. ISO 7816-4 base instruction.
    /// `[HIGH]`
    ExternalAuthenticate = 0x82,
    /// MANAGE SECURITY ENVIRONMENT — select the key/algorithm reference
    /// ahead of PSO signing. ISO 7816-4 base instruction. `[HIGH]` — the
    /// instruction byte, its use ahead of signing, and the Digital Signature
    /// Template CRT layout are now evidence-based, not a blind guess; see
    /// [`manage_security_environment`].
    ManageSecurityEnvironment = 0x22,
    /// GENERATE ASYMMETRIC KEY PAIR. `[GUESS: 0x46 per ISO 7816-8's own
    /// table]` — note both PIV and OpenPGP in this workspace use `0x47` for
    /// the identical concept on their own cards, so `0x47` is a live
    /// alternative if `0x46` comes back `6D00`.
    GenerateAsymmetricKeyPair = 0x46,
    /// PERFORM SECURITY OPERATION — used here for both LOAD HASH
    /// (`P1=0x90 P2=0xA0`, see [`pso_load_hash`]) and COMPUTE DIGITAL
    /// SIGNATURE (`P1=0x9E P2=0x9A`, see [`pso_compute_signature`]). ISO
    /// 7816-8 base instruction; byte-identical to this workspace's own
    /// `keyroost-openpgp::Instruction::PerformSecurityOperation` (`0x2A`),
    /// which is tested against real OpenPGP-card hardware, *and* to the
    /// exact sequence OpenSC's `card-cedulauy.c` driver issues against a
    /// real, deployed IAS-Classic-family card. `[HIGH]`
    PerformSecurityOperation = 0x2A,
    /// READ BINARY — read an EF (certificate file), either after a SELECT
    /// FILE or via a short-EF-id in P1. ISO 7816-4 base instruction. `[HIGH]`
    ReadBinary = 0xB0,
    /// UPDATE BINARY — write/replace an EF's contents. ISO 7816-4 base
    /// instruction. `[HIGH]`
    UpdateBinary = 0xD6,
    /// GET RESPONSE — pull the next chunk of a `61xx`-chained reply. ISO
    /// 7816-4 base instruction. `[HIGH]`
    GetResponse = 0xC0,
}

impl Instruction {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Slots (key/certificate containers) and the FID table
// ---------------------------------------------------------------------------

/// One key/certificate container. IAS-ECC profiles commonly expose a small,
/// fixed set of containers rather than PIV's tagged-object model. **The
/// key-reference bytes and file IDs are `[GUESS]` placeholders** — a real
/// card's layout is issuer/profile-specific and set at provisioning time.
/// [`FidTable`] exists so correcting the FID half of this, once traced, is a
/// config change (`--fid <slot>=<hex>`), not a rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Authentication container.
    Authentication,
    /// Digital-signature (non-repudiation) container.
    Signature,
    /// Key-management (confidentiality/decryption) container.
    KeyManagement,
}

impl Slot {
    /// Private-key reference (used in MSE/GENERATE/PSO tags). `[GUESS]`
    #[must_use]
    pub const fn key_ref(self) -> u8 {
        match self {
            Slot::Authentication => 0x81,
            Slot::Signature => 0x82,
            Slot::KeyManagement => 0x83,
        }
    }

    /// Default certificate file ID (2 bytes), before any `--fid` override.
    /// `[GUESS]`
    #[must_use]
    pub const fn default_cert_fid(self) -> u16 {
        match self {
            Slot::Authentication => 0x0101,
            Slot::Signature => 0x0102,
            Slot::KeyManagement => 0x0103,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Slot::Authentication => "authentication",
            Slot::Signature => "signature",
            Slot::KeyManagement => "key management",
        }
    }

    #[must_use]
    pub const fn all() -> [Slot; 3] {
        [Slot::Authentication, Slot::Signature, Slot::KeyManagement]
    }
}

/// Runtime per-slot certificate FID table, defaulting to
/// [`Slot::default_cert_fid`] but overridable per slot — the "cheap to fix
/// once traced" mechanism the fixed/configurable-FID design calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FidTable {
    pub authentication: u16,
    pub signature: u16,
    pub key_management: u16,
}

impl Default for FidTable {
    fn default() -> Self {
        Self {
            authentication: Slot::Authentication.default_cert_fid(),
            signature: Slot::Signature.default_cert_fid(),
            key_management: Slot::KeyManagement.default_cert_fid(),
        }
    }
}

impl FidTable {
    #[must_use]
    pub const fn fid_for(&self, slot: Slot) -> u16 {
        match slot {
            Slot::Authentication => self.authentication,
            Slot::Signature => self.signature,
            Slot::KeyManagement => self.key_management,
        }
    }
}

// ---------------------------------------------------------------------------
// Key/admin algorithms
// ---------------------------------------------------------------------------

/// A key algorithm this crate can ask IAS to generate/use, identified by its
/// ISO 7816-8 algorithm-reference byte. **Deliberately a separate type from
/// `keyroost_piv::KeyAlg`**: PIV's algorithm-ID bytes (e.g. `EccP256 = 0x11`,
/// SP 800-78's table) have no meaning in ISO 7816-8's generic
/// algorithm-reference space, so reusing that type would silently send the
/// wrong byte on the wire. [`KeyAlg::to_piv_alg`] bridges the two only where
/// DER construction (which cares about key *shape*, not wire ID) needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    Rsa2048,
    Rsa3072,
    EccP256,
    EccP384,
}

impl KeyAlg {
    /// Algorithm-reference byte for the GENERATE KEY PAIR CRT's tag-`0x80`
    /// subfield. `[GUESS]` — ISO 7816-8 leaves exact algorithm-reference
    /// numbering to the card's own registered table; these are placeholders,
    /// not derived from a spec this crate had access to.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            KeyAlg::Rsa2048 => 0x02,
            KeyAlg::Rsa3072 => 0x04,
            KeyAlg::EccP256 => 0x0C,
            KeyAlg::EccP384 => 0x0D,
        }
    }

    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x02 => Some(KeyAlg::Rsa2048),
            0x04 => Some(KeyAlg::Rsa3072),
            0x0C => Some(KeyAlg::EccP256),
            0x0D => Some(KeyAlg::EccP384),
            _ => None,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            KeyAlg::Rsa2048 => "RSA-2048",
            KeyAlg::Rsa3072 => "RSA-3072",
            KeyAlg::EccP256 => "ECC P-256",
            KeyAlg::EccP384 => "ECC P-384",
        }
    }

    /// Bridge to `keyroost_piv::KeyAlg`, used only where this crate hands key
    /// material to `keyroost-piv`'s DER (CSR/self-sign/SPKI) builders — those
    /// only care about key shape (RSA modulus size, EC curve), not the wire
    /// algorithm-ID byte, so the conversion is exact and lossless.
    #[must_use]
    pub const fn to_piv_alg(self) -> keyroost_piv::KeyAlg {
        match self {
            KeyAlg::Rsa2048 => keyroost_piv::KeyAlg::Rsa2048,
            KeyAlg::Rsa3072 => keyroost_piv::KeyAlg::Rsa3072,
            KeyAlg::EccP256 => keyroost_piv::KeyAlg::EccP256,
            KeyAlg::EccP384 => keyroost_piv::KeyAlg::EccP384,
        }
    }

    /// The inverse of [`KeyAlg::to_piv_alg`], for the direction that reads an
    /// algorithm back out of `keyroost_piv`'s DER parsers (a slot's
    /// certificate, or a `--load-pubkey` file). `None` for a `keyroost_piv`
    /// algorithm with no IAS-side equivalent in this crate's narrower set
    /// (e.g. RSA-1024/4096, Ed25519, X25519).
    #[must_use]
    pub const fn from_piv_alg(alg: keyroost_piv::KeyAlg) -> Option<Self> {
        match alg {
            keyroost_piv::KeyAlg::Rsa2048 => Some(KeyAlg::Rsa2048),
            keyroost_piv::KeyAlg::Rsa3072 => Some(KeyAlg::Rsa3072),
            keyroost_piv::KeyAlg::EccP256 => Some(KeyAlg::EccP256),
            keyroost_piv::KeyAlg::EccP384 => Some(KeyAlg::EccP384),
            _ => None,
        }
    }

    /// Algorithm-reference byte for [`manage_security_environment`]'s
    /// Digital Signature Template — a *different* field from [`KeyAlg::id`]
    /// above, confirmed by OpenSC's `card-idprime.c` (the driver for the
    /// eToken 5300's actual chip family — see [`CANDIDATE_AIDS`]) to encode
    /// the signing hash+padding scheme, not the key size/curve: `0x42` for
    /// RSA-PKCS1-v1.5 with SHA-256 (what this crate's own `prepared_block`
    /// always builds for RSA), `0x44` for generic EC signing. `[HIGH]` —
    /// unlike [`KeyAlg::id`] (still `[GUESS]`, and used only by the
    /// unconfirmed GENERATE ASYMMETRIC KEY PAIR CRT), this value is real.
    #[must_use]
    pub const fn mse_sign_algo_id(self) -> u8 {
        match self {
            KeyAlg::Rsa2048 | KeyAlg::Rsa3072 => 0x42,
            KeyAlg::EccP256 | KeyAlg::EccP384 => 0x44,
        }
    }
}

/// Cipher for the GET CHALLENGE / EXTERNAL AUTHENTICATE admin-key round.
/// `[UNKNOWN]` — see `keyroost-transport::ias::admin_crypt`'s doc comment;
/// this enum exists so swapping the cipher, once traced, is a one-match-arm
/// edit rather than a signature change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IasAdminAlg {
    TripleDes,
    Aes128,
}

impl IasAdminAlg {
    #[must_use]
    pub const fn block_size(self) -> usize {
        match self {
            IasAdminAlg::TripleDes => 8,
            IasAdminAlg::Aes128 => 16,
        }
    }

    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            IasAdminAlg::TripleDes => 24,
            IasAdminAlg::Aes128 => 16,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            IasAdminAlg::TripleDes => "3DES",
            IasAdminAlg::Aes128 => "AES-128",
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// An out-of-range PIN/PUK/admin-secret length. Never pad/truncate a secret
/// into a different valid-length one and burn a retry against the card —
/// same discipline as `keyroost_piv::PinLengthError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinLengthError {
    /// The rejected length, in bytes.
    pub len: usize,
}

impl core::fmt::Display for PinLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IAS PIN/PUK must be 4-8 bytes (got {})", self.len)
    }
}

impl std::error::Error for PinLengthError {}

/// A malformed or unexpected card response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer ended before a length-prefixed value did.
    Truncated,
    /// Expected the `7F49` public-key template, found something else.
    NotPublicKeyTemplate,
    /// A BER length used an unsupported form (indefinite, or >2-byte long form).
    BadLength,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "IAS response truncated"),
            ParseError::NotPublicKeyTemplate => {
                write!(f, "IAS response is not a 7F49 public-key template")
            }
            ParseError::BadLength => write!(f, "IAS response used an unsupported BER length form"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Pad a 4-16 byte PIN/PUK to a fixed 16-byte field with `0x00`. `[HIGH]` —
/// confirmed by OpenSC issue #3488 and its fix, PR #3493: a real SafeNet
/// eToken 5100/5110 SC (same Gemalto IDPrime chip family as the 5300 — see
/// [`CANDIDATE_AIDS`]) rejected an unpadded/8-byte-padded VERIFY with
/// `SW 6700` and required a 16-byte, `0x00`-padded field instead. Unlike
/// PIV's fixed 8-byte `0xFF`-padded field, this is a different size *and* a
/// different pad byte, not just a length bump — verified directly from that
/// issue's APDU traces, not inferred.
fn pad_pin(pin: &[u8]) -> Result<Zeroizing<Vec<u8>>, PinLengthError> {
    if !(4..=16).contains(&pin.len()) {
        return Err(PinLengthError { len: pin.len() });
    }
    let mut out = Zeroizing::new(vec![0x00u8; 16]);
    out[..pin.len()].copy_from_slice(pin);
    Ok(out)
}

// ---------------------------------------------------------------------------
// APDU builders
// ---------------------------------------------------------------------------

/// SELECT the IAS applet by `aid` (case 4: a trailing `Le` requests whatever
/// property template the card returns on success). `P2=0x00` ("return FCI,
/// first/only occurrence") rather than PIV/Yubico's `0x0C` ("no response
/// data") — `[HIGH]`, confirmed by OpenSC's `card-cedulauy.c` driver for a
/// real, deployed IAS-Classic-family card (Uruguay's national eID), which
/// builds this exact `00 A4 04 00 <Lc> <aid>` SELECT and reads an FCI back.
#[must_use]
pub fn select(aid: &[u8]) -> Vec<u8> {
    let mut apdu = build_apdu(0x00, Instruction::Select.code(), 0x04, 0x00, aid);
    apdu.push(0x00);
    apdu
}

/// VERIFY the PIN. `[GUESS]` P2 reference — see [`PIN_REF_USER`].
pub fn verify_pin(pin: &[u8]) -> Result<Vec<u8>, PinLengthError> {
    Ok(build_apdu(
        0x00,
        Instruction::Verify.code(),
        0x00,
        PIN_REF_USER,
        &pad_pin(pin)?,
    ))
}

/// VERIFY with an empty body — queries the PIN retry counter without
/// consuming a try. Case 1 (no `Lc`, no `Le`).
#[must_use]
pub fn verify_pin_status() -> Vec<u8> {
    vec![0x00, Instruction::Verify.code(), 0x00, PIN_REF_USER]
}

/// CHANGE REFERENCE DATA: change the PIN.
pub fn change_reference_data(old: &[u8], new: &[u8]) -> Result<Vec<u8>, PinLengthError> {
    let mut body = pad_pin(old)?.to_vec();
    body.extend_from_slice(&pad_pin(new)?);
    Ok(build_apdu(
        0x00,
        Instruction::ChangeReferenceData.code(),
        0x00,
        PIN_REF_USER,
        &body,
    ))
}

/// CHANGE REFERENCE DATA against the admin/SO key reference, rather than
/// the PIN: raw `old`/`new` key bytes, unpadded (unlike the PIN's fixed
/// 8-byte field — a symmetric key is already a fixed algorithm-defined
/// length, so there's nothing to pad). `[HIGH]` for reusing CHANGE
/// REFERENCE DATA's own instruction byte for a non-PIN reference (that's
/// exactly what ISO 7816-4 defines the "reference data" concept to cover);
/// `[GUESS]` for [`ADMIN_KEY_REF`] itself.
#[must_use]
pub fn change_admin_key(old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(old.len() + new.len());
    body.extend_from_slice(old);
    body.extend_from_slice(new);
    build_apdu(
        0x00,
        Instruction::ChangeReferenceData.code(),
        0x00,
        ADMIN_KEY_REF,
        &body,
    )
}

/// RESET RETRY COUNTER: unblock the PIN with an unblock code (PUK), setting
/// a new PIN in the same command. `[GUESS]` body layout — modeled on PIV's
/// own unblock (concatenated padded PUK + padded new PIN).
pub fn reset_retry_counter(puk: &[u8], new_pin: &[u8]) -> Result<Vec<u8>, PinLengthError> {
    let mut body = pad_pin(puk)?.to_vec();
    body.extend_from_slice(&pad_pin(new_pin)?);
    Ok(build_apdu(
        0x00,
        Instruction::ResetRetryCounter.code(),
        0x00,
        PIN_REF_USER,
        &body,
    ))
}

/// GET CHALLENGE: request an `le`-byte nonce from the card ahead of EXTERNAL
/// AUTHENTICATE. `le` should match the admin algorithm's block size (8 for
/// 3DES, 16 for AES — see [`IasAdminAlg::block_size`]). `P2` selects the
/// challenge length rather than being a fixed `0x00`: `[HIGH]`, confirmed by
/// OpenSC's `card-idprime.c` for the eToken 5300's own chip family — `0x01`
/// for an 8-byte challenge, `0x00` for 16 bytes, matching this crate's own
/// `IasAdminAlg` block sizes exactly.
#[must_use]
pub fn get_challenge(le: u8) -> Vec<u8> {
    let p2 = if le == 8 { 0x01 } else { 0x00 };
    build_apdu_get(0x00, Instruction::GetChallenge.code(), 0x00, p2, le)
}

/// EXTERNAL AUTHENTICATE: present the host's encrypted response to a prior
/// GET CHALLENGE, under `admin_key_ref`. `[HIGH]` framing; `response`'s
/// construction (cipher/mode/MAC) is entirely `[UNKNOWN]` — see
/// `keyroost-transport::ias::admin_crypt`.
#[must_use]
pub fn external_authenticate(admin_key_ref: u8, response: &[u8]) -> Vec<u8> {
    build_apdu(
        0x00,
        Instruction::ExternalAuthenticate.code(),
        0x00,
        admin_key_ref,
        response,
    )
}

/// MANAGE SECURITY ENVIRONMENT — SET the Digital Signature Template (DST)
/// ahead of PSO:COMPUTE DIGITAL SIGNATURE, selecting which key/algorithm the
/// next signature operation uses. `[HIGH]` — confirmed by OpenSC's
/// `card-cedulauy.c` driver, which issues exactly this APDU
/// (`00 22 41 B6 <Lc> 84 01 <keyref> 80 01 <algo>`) before every signature.
/// Tag `0xB6` (DST) is also the ISO 7816-8-correct choice for a *signature*
/// key selection specifically (as opposed to `0xB8`, Confidentiality
/// Template, used for decipher/confidentiality operations) — unlike the
/// [`generate_key_pair`] CRT below, this one is evidence-based, not a blind
/// guess, and is called unconditionally by
/// [`keyroost_transport`](../../keyroost_transport/index.html)'s
/// `IasSession::sign` ahead of every signature.
#[must_use]
pub fn manage_security_environment(slot: Slot, alg: KeyAlg) -> Vec<u8> {
    let mut inner = Vec::with_capacity(6);
    push_tlv(&mut inner, &[0x84], &[slot.key_ref()]);
    push_tlv(&mut inner, &[0x80], &[alg.mse_sign_algo_id()]);
    let mut crt = Vec::with_capacity(inner.len() + 2);
    push_tlv(&mut crt, &[0xB6], &inner);
    build_apdu(
        0x00,
        Instruction::ManageSecurityEnvironment.code(),
        0x41,
        0xB6,
        &crt,
    )
}

/// The CRT (control reference template) [`generate_key_pair`] wraps its
/// algorithm/key-reference in. **Not the same tag/field-order the now-
/// confirmed [`manage_security_environment`] uses** — that evidence covers
/// MSE:SET DST ahead of signing, not GENERATE ASYMMETRIC KEY PAIR itself (the
/// real card this crate's other evidence comes from, Uruguay's eID, has no
/// user-triggered key generation to observe at all — keys are provisioned
/// at issuance). `[GUESS]` tag choice — a real card may instead expect
/// `0xA6`, `0xB6` matching MSE:SET's own tag, or no outer wrapper at all.
fn generate_key_pair_crt(slot: Slot, alg: KeyAlg) -> Vec<u8> {
    let mut inner = Vec::with_capacity(6);
    push_tlv(&mut inner, &[0x80], &[alg.id()]);
    push_tlv(&mut inner, &[0x84], &[slot.key_ref()]);
    let mut crt = Vec::with_capacity(inner.len() + 2);
    push_tlv(&mut crt, &[0xB8], &inner);
    crt
}

/// GENERATE ASYMMETRIC KEY PAIR: `00 46 00 00 Lc <CRT> 00`. The card creates
/// a fresh private key in `slot` and returns its public key (`7F49`
/// template, parsed by [`parse_generated_public_key`]). Requires prior
/// admin-key authentication. `[GUESS]` INS/CRT — see [`Instruction::GenerateAsymmetricKeyPair`].
#[must_use]
pub fn generate_key_pair(slot: Slot, alg: KeyAlg) -> Vec<u8> {
    let crt = generate_key_pair_crt(slot, alg);
    let mut apdu = build_apdu(
        0x00,
        Instruction::GenerateAsymmetricKeyPair.code(),
        0x00,
        0x00,
        &crt,
    );
    apdu.push(0x00);
    apdu
}

/// PSO:LOAD HASH (a.k.a. PSO:HASH): push the to-be-signed digest — a full
/// PKCS#1 v1.5 DigestInfo for RSA, or the raw hash for ECDSA; this layer
/// never hashes — to the card ahead of an empty-body
/// [`pso_compute_signature`]. `[HIGH]` — confirmed by OpenSC's
/// `card-cedulauy.c` driver: `00 2A 90 A0 <Lc> 90 <len> <data>` (tag `0x90`
/// wraps the digest), no response expected. On the real card this evidence
/// comes from, the two-step MSE:SET DST → PSO:HASH → empty PSO:CDS sequence
/// *replaces* sending the digest directly in PSO:CDS's own body — see
/// `IasSession::sign`, which now does exactly that sequence unconditionally
/// rather than the single-step form this crate originally shipped with.
#[must_use]
pub fn pso_load_hash(data: &[u8]) -> Vec<u8> {
    let mut tlv = Vec::with_capacity(data.len() + 2);
    push_tlv(&mut tlv, &[0x90], data);
    build_apdu_ext(
        0x00,
        Instruction::PerformSecurityOperation.code(),
        0x90,
        0xA0,
        &tlv,
        None,
    )
}

/// Command-chaining form of [`pso_load_hash`], for cards/readers that reject
/// a single extended-length PSO:HASH — an RSA-3072/4096 DigestInfo can
/// exceed the 255-byte short-form ceiling.
#[must_use]
pub fn pso_load_hash_chained(data: &[u8], max_chunk: usize) -> Vec<Vec<u8>> {
    let mut tlv = Vec::with_capacity(data.len() + 2);
    push_tlv(&mut tlv, &[0x90], data);
    chain_apdu(
        0x00,
        Instruction::PerformSecurityOperation.code(),
        0x90,
        0xA0,
        &tlv,
        max_chunk,
        None,
    )
}

/// PSO:COMPUTE DIGITAL SIGNATURE, single short/extended-length APDU:
/// `00 2A 9E 9A <Lc> <data> <Le>` — byte-identical framing to this
/// workspace's own `keyroost_openpgp` PSO:CDS. `[HIGH]` framing. Two calling
/// conventions are both live in this workspace: pass the caller-prepared
/// DigestInfo/hash directly as `data` (this crate's original, unconfirmed
/// single-step guess), or pass `&[]` after a prior [`pso_load_hash`] — the
/// now-evidence-based two-step form `IasSession::sign` actually uses (see
/// that function's doc comment).
#[must_use]
pub fn pso_compute_signature(data: &[u8]) -> Vec<u8> {
    build_apdu_ext(
        0x00,
        Instruction::PerformSecurityOperation.code(),
        0x9E,
        0x9A,
        data,
        Some(0),
    )
}

/// Command-chaining form of [`pso_compute_signature`], for cards/readers
/// that reject a single extended-length PSO:CDS — the same fallback shape
/// this workspace's PIV/OpenPGP layers use for their own large-payload
/// commands.
#[must_use]
pub fn pso_compute_signature_chained(data: &[u8], max_chunk: usize) -> Vec<Vec<u8>> {
    chain_apdu(
        0x00,
        Instruction::PerformSecurityOperation.code(),
        0x9E,
        0x9A,
        data,
        max_chunk,
        Some(0x00),
    )
}

/// SELECT FILE (an EF under the current DF) by 2-byte FID:
/// `00 A4 02 0C 02 <fid_hi> <fid_lo>`. `[HIGH]` ISO 7816-4 base SELECT
/// semantics; whether the target card needs this before READ/UPDATE BINARY
/// at all, vs. supporting short-EF-id addressing directly (see
/// [`read_binary_short_ef`]), is `[GUESS]`.
#[must_use]
pub fn select_file_fid(fid: u16) -> Vec<u8> {
    build_apdu(
        0x00,
        Instruction::Select.code(),
        0x02,
        0x0C,
        &[(fid >> 8) as u8, fid as u8],
    )
}

/// READ BINARY at `offset` after a prior [`select_file_fid`], requesting up
/// to `le` bytes (`0` = "up to 65536" in extended form). `[HIGH]` framing.
#[must_use]
pub fn read_binary(offset: u16, le: u16) -> Vec<u8> {
    build_apdu_ext(
        0x00,
        Instruction::ReadBinary.code(),
        (offset >> 8) as u8,
        offset as u8,
        &[],
        Some(le),
    )
}

/// READ BINARY addressed directly by a short EF identifier in P1 (bit 0x80
/// set, low 5 bits = `sfi`), without a prior SELECT FILE. `[GUESS]` whether
/// the target card supports this addressing mode at all.
#[must_use]
pub fn read_binary_short_ef(sfi: u8, offset: u8, le: u8) -> Vec<u8> {
    build_apdu_get(
        0x00,
        Instruction::ReadBinary.code(),
        0x80 | (sfi & 0x1F),
        offset,
        le,
    )
}

/// UPDATE BINARY at `offset` after a prior [`select_file_fid`], single
/// short/extended-length APDU. `[HIGH]` framing.
#[must_use]
pub fn update_binary(offset: u16, data: &[u8]) -> Vec<u8> {
    build_apdu_ext(
        0x00,
        Instruction::UpdateBinary.code(),
        (offset >> 8) as u8,
        offset as u8,
        data,
        None,
    )
}

/// Command-chaining form of [`update_binary`], for cards/readers that reject
/// a single extended-length UPDATE BINARY (certificate import routinely
/// exceeds 255 bytes).
#[must_use]
pub fn update_binary_chained(offset: u16, data: &[u8], max_chunk: usize) -> Vec<Vec<u8>> {
    chain_apdu(
        0x00,
        Instruction::UpdateBinary.code(),
        (offset >> 8) as u8,
        offset as u8,
        data,
        max_chunk,
        None,
    )
}

/// GET RESPONSE: pull the next chunk of a `61xx`-chained reply.
#[must_use]
pub fn get_response() -> Vec<u8> {
    vec![0x00, Instruction::GetResponse.code(), 0x00, 0x00, 0x00]
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Find the first top-level TLV with a single-byte `tag` in `buf`, returning
/// its value bytes. Bounds-checked; never panics on truncated/garbage input.
#[must_use]
pub fn find_tlv(buf: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < buf.len() {
        let t = buf[i];
        let (len, header) = read_ber_len(buf.get(i + 1..)?).ok()?;
        let start = i + 1 + header;
        let end = start.checked_add(len)?;
        let value = buf.get(start..end)?;
        if t == tag {
            return Some(value);
        }
        i = end;
    }
    None
}

/// Read a BER-TLV definite length at the start of `buf`, returning
/// `(length, header_byte_count)`. Short form and the 1-/2-byte long forms
/// only; rejects indefinite (`0x80`) and >2-byte forms as [`ParseError::BadLength`].
pub fn read_ber_len(buf: &[u8]) -> Result<(usize, usize), ParseError> {
    match buf.first() {
        None => Err(ParseError::Truncated),
        Some(&b) if b < 0x80 => Ok((b as usize, 1)),
        Some(&0x81) => {
            let len = *buf.get(1).ok_or(ParseError::Truncated)?;
            Ok((len as usize, 2))
        }
        Some(&0x82) => {
            let hi = *buf.get(1).ok_or(ParseError::Truncated)? as usize;
            let lo = *buf.get(2).ok_or(ParseError::Truncated)? as usize;
            Ok(((hi << 8) | lo, 3))
        }
        Some(_) => Err(ParseError::BadLength),
    }
}

/// Parse a `7F49` generated-public-key template into a [`PublicKey`]. Same
/// tag and inner-TLV conventions PIV uses (`81`/`82` RSA modulus/exponent,
/// `86` EC point) — ISO 7816-8's own SubjectPublicKeyInfo-in-TLV wrapper,
/// `[HIGH]` for the tag itself, `[GUESS]` for whether IAS populates it
/// identically.
pub fn parse_generated_public_key(buf: &[u8]) -> Result<PublicKey, ParseError> {
    if buf.get(..2) != Some(&[0x7F, 0x49][..]) {
        return Err(ParseError::NotPublicKeyTemplate);
    }
    let (len, header) = read_ber_len(&buf[2..])?;
    let start = 2 + header;
    let end = start.checked_add(len).ok_or(ParseError::Truncated)?;
    let inner = buf.get(start..end).ok_or(ParseError::Truncated)?;
    if let Some(point) = find_tlv(inner, 0x86) {
        return Ok(PublicKey::Ecc {
            point: point.to_vec(),
        });
    }
    let modulus = find_tlv(inner, 0x81).ok_or(ParseError::NotPublicKeyTemplate)?;
    let exponent = find_tlv(inner, 0x82).ok_or(ParseError::NotPublicKeyTemplate)?;
    Ok(PublicKey::Rsa {
        modulus: modulus.to_vec(),
        exponent: exponent.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_bytes() {
        let aid = [0xA0, 0x00, 0x00, 0x01];
        assert_eq!(
            select(&aid),
            vec![0x00, 0xA4, 0x04, 0x00, 0x04, 0xA0, 0x00, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn candidate_aids_include_the_confirmed_cedulauy_aid() {
        // Real, evidenced AID (OpenSC card-cedulauy.c) — must stay in the
        // list, and the select() APDU built from it must round-trip.
        let real_aid = [
            0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00,
        ];
        assert!(CANDIDATE_AIDS.contains(&&real_aid[..]));
    }

    #[test]
    fn candidate_aids_include_a_truncated_idprime_prefix() {
        // The IDPrime AID's own one-byte-truncated prefix must be present,
        // immediately after the full AID, as an ISO 7816-4 partial-DF-name
        // fallback (mirrors keyroost-piv's own AID truncation).
        let full = [
            0xA0, 0x00, 0x00, 0x00, 0x18, 0x80, 0x00, 0x00, 0x00, 0x06, 0x62,
        ];
        let prefix = [0xA0, 0x00, 0x00, 0x00, 0x18, 0x80, 0x00, 0x00, 0x00, 0x06];
        let full_pos = CANDIDATE_AIDS
            .iter()
            .position(|a| *a == &full[..])
            .expect("full IDPrime AID missing");
        let prefix_pos = CANDIDATE_AIDS
            .iter()
            .position(|a| *a == &prefix[..])
            .expect("truncated IDPrime prefix missing");
        assert_eq!(prefix_pos, full_pos + 1);
        // Every byte of the prefix must actually match the full AID's
        // leading bytes -- a stale hand-edit here would silently produce an
        // unrelated AID rather than a true prefix.
        assert_eq!(&full[..prefix.len()], &prefix[..]);
    }

    #[test]
    fn verify_pin_pads_to_sixteen() {
        // Confirmed shape (OpenSC issue #3488 / PR #3493, real eToken 5300
        // trace): 00 20 00 11 10 <pin digits> 00-padded to 16 bytes total.
        let apdu = verify_pin(b"1234").unwrap();
        assert_eq!(apdu[..5], [0x00, 0x20, 0x00, PIN_REF_USER, 0x10]);
        assert_eq!(apdu.len(), 5 + 16);
        assert_eq!(
            &apdu[5..],
            &[0x31, 0x32, 0x33, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn verify_pin_rejects_out_of_range() {
        assert_eq!(verify_pin(b"123").unwrap_err(), PinLengthError { len: 3 });
        assert_eq!(
            verify_pin(b"12345678901234567").unwrap_err(),
            PinLengthError { len: 17 }
        );
    }

    #[test]
    fn verify_pin_status_bytes() {
        assert_eq!(verify_pin_status(), vec![0x00, 0x20, 0x00, PIN_REF_USER]);
    }

    #[test]
    fn change_reference_data_bytes() {
        let apdu = change_reference_data(b"1234", b"5678").unwrap();
        assert_eq!(apdu[..4], [0x00, 0x24, 0x00, PIN_REF_USER]);
        assert_eq!(apdu[4], 0x20); // Lc: two padded 16-byte fields
        assert_eq!(
            &apdu[5..21],
            &[0x31, 0x32, 0x33, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            &apdu[21..37],
            &[0x35, 0x36, 0x37, 0x38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn change_admin_key_bytes() {
        let apdu = change_admin_key(&[0x11; 24], &[0x22; 24]);
        assert_eq!(apdu[..4], [0x00, 0x24, 0x00, ADMIN_KEY_REF]);
        assert_eq!(apdu[4], 48); // Lc: unpadded old+new, no fixed 8-byte field
        assert_eq!(&apdu[5..29], &[0x11u8; 24][..]);
        assert_eq!(&apdu[29..53], &[0x22u8; 24][..]);
    }

    #[test]
    fn reset_retry_counter_bytes() {
        let apdu = reset_retry_counter(b"00000000", b"1234").unwrap();
        assert_eq!(apdu[..4], [0x00, 0x2C, 0x00, PIN_REF_USER]);
        assert_eq!(apdu[4], 0x20);
    }

    #[test]
    fn get_challenge_bytes() {
        // Confirmed shape (card-idprime.c): P2=0x01 for an 8-byte challenge,
        // P2=0x00 otherwise.
        assert_eq!(get_challenge(8), vec![0x00, 0x84, 0x00, 0x01, 0x08]);
        assert_eq!(get_challenge(16), vec![0x00, 0x84, 0x00, 0x00, 0x10]);
    }

    #[test]
    fn external_authenticate_bytes() {
        assert_eq!(
            external_authenticate(ADMIN_KEY_REF, &[0xAA; 8]),
            vec![
                0x00,
                0x82,
                0x00,
                ADMIN_KEY_REF,
                0x08,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA
            ]
        );
    }

    #[test]
    fn generate_key_pair_bytes() {
        // 00 46 00 00 08 B8 06 80 01 0C 84 01 81 00 (P-256 in Authentication slot)
        let apdu = generate_key_pair(Slot::Authentication, KeyAlg::EccP256);
        assert_eq!(
            apdu,
            vec![
                0x00, 0x46, 0x00, 0x00, 0x08, 0xB8, 0x06, 0x80, 0x01, 0x0C, 0x84, 0x01, 0x81, 0x00
            ]
        );
    }

    #[test]
    fn manage_security_environment_bytes() {
        // Confirmed shape (OpenSC card-cedulauy.c): 00 22 41 B6 <Lc>
        // B6 <len> { 84 01 <keyref>  80 01 <algo> }
        // Algorithm-reference byte itself is the card-idprime.c-confirmed
        // value (0x42 RSA / 0x44 EC PKCS1-SHA digital-signature scheme), not
        // KeyAlg::id() (which is a separate, still-unconfirmed byte space
        // used only by GENERATE ASYMMETRIC KEY PAIR).
        let apdu = manage_security_environment(Slot::Signature, KeyAlg::Rsa2048);
        assert_eq!(apdu[..4], [0x00, 0x22, 0x41, 0xB6]);
        assert_eq!(apdu[4], 0x08); // Lc: CRT length
        assert_eq!(
            &apdu[5..],
            &[0xB6, 0x06, 0x84, 0x01, 0x82, 0x80, 0x01, 0x42]
        );
    }

    #[test]
    fn pso_load_hash_bytes() {
        // Confirmed shape (OpenSC card-cedulauy.c): 00 2A 90 A0 <Lc> 90 <len> <data>
        let apdu = pso_load_hash(&[0xAA, 0xBB]);
        assert_eq!(
            apdu,
            vec![0x00, 0x2A, 0x90, 0xA0, 0x04, 0x90, 0x02, 0xAA, 0xBB]
        );
    }

    #[test]
    fn pso_load_hash_extended_form_over_255() {
        // An RSA-3072 DigestInfo is well over the 255-byte short-form
        // ceiling; must not panic (build_apdu would).
        let data = vec![0x11u8; 384];
        let apdu = pso_load_hash(&data);
        assert_eq!(&apdu[..5], &[0x00, 0x2A, 0x90, 0xA0, 0x00]);
        let lc = ((apdu[5] as usize) << 8) | apdu[6] as usize;
        // Inner TLV: 1 tag byte + 3-byte long-form BER length (0x82 hi lo) + data.
        assert_eq!(lc, 1 + 3 + 384);
        assert_eq!(&apdu[7..11], &[0x90, 0x82, 0x01, 0x80]); // tag 0x90, 2-byte BER length form (384 = 0x0180)
        assert_eq!(&apdu[11..11 + 384], data.as_slice());
    }

    #[test]
    fn pso_load_hash_chained_reassembles_to_extended_body() {
        let data = vec![0x22u8; 384];
        let extended = pso_load_hash(&data);
        let ext_lc = ((extended[5] as usize) << 8) | extended[6] as usize;
        let ext_body = &extended[7..7 + ext_lc];

        let chunks = pso_load_hash_chained(&data, 254);
        assert!(chunks.len() > 1);
        let last = chunks.len() - 1;
        let mut reassembled = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let expected_cla = if i < last { 0x10 } else { 0x00 };
            assert_eq!(chunk[0], expected_cla);
            assert_eq!(&chunk[1..4], &[0x2A, 0x90, 0xA0]);
            let lc = chunk[4] as usize;
            reassembled.extend_from_slice(&chunk[5..5 + lc]);
            assert_eq!(chunk.len(), 5 + lc); // PSO:HASH requests no Le, on any link
        }
        assert_eq!(reassembled, ext_body);
    }

    #[test]
    fn pso_compute_signature_short_form() {
        let apdu = pso_compute_signature(&[0x01, 0x02, 0x03]);
        assert_eq!(
            apdu,
            vec![0x00, 0x2A, 0x9E, 0x9A, 0x03, 0x01, 0x02, 0x03, 0x00]
        );
    }

    #[test]
    fn pso_compute_signature_extended_form_over_255() {
        let data = vec![0x5Au8; 256];
        let apdu = pso_compute_signature(&data);
        assert_eq!(&apdu[..5], &[0x00, 0x2A, 0x9E, 0x9A, 0x00]);
        assert_eq!(&apdu[5..7], &[0x01, 0x00]); // 256 = 0x0100
    }

    #[test]
    fn pso_compute_signature_chained_reassembles_to_extended_body() {
        let data = vec![0x5Au8; 256]; // RSA-2048 prepared block
        let extended = pso_compute_signature(&data);
        let ext_lc = ((extended[5] as usize) << 8) | extended[6] as usize;
        let ext_body = &extended[7..7 + ext_lc];

        let chunks = pso_compute_signature_chained(&data, 254);
        assert!(chunks.len() > 1);
        let last = chunks.len() - 1;
        let mut reassembled = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let expected_cla = if i < last { 0x10 } else { 0x00 };
            assert_eq!(chunk[0], expected_cla);
            assert_eq!(&chunk[1..4], &[0x2A, 0x9E, 0x9A]);
            let lc = chunk[4] as usize;
            reassembled.extend_from_slice(&chunk[5..5 + lc]);
            if i == last {
                assert_eq!(&chunk[5 + lc..], &[0x00]);
            } else {
                assert_eq!(chunk.len(), 5 + lc);
            }
        }
        assert_eq!(reassembled, ext_body);
    }

    #[test]
    fn select_file_fid_bytes() {
        assert_eq!(
            select_file_fid(0x0101),
            vec![0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x01]
        );
    }

    #[test]
    fn read_binary_bytes() {
        assert_eq!(read_binary(0x0010, 256), vec![0x00, 0xB0, 0x00, 0x10, 0x00]);
    }

    #[test]
    fn read_binary_short_ef_bytes() {
        assert_eq!(
            read_binary_short_ef(0x01, 0x00, 0x00),
            vec![0x00, 0xB0, 0x81, 0x00, 0x00]
        );
    }

    #[test]
    fn update_binary_chained_reassembles() {
        let data = vec![0x11u8; 400];
        let extended = update_binary(0, &data);
        let ext_lc = ((extended[5] as usize) << 8) | extended[6] as usize;
        let ext_body = &extended[7..7 + ext_lc];

        let chunks = update_binary_chained(0, &data, 254);
        assert!(chunks.len() > 1);
        let mut reassembled = Vec::new();
        for chunk in &chunks {
            let lc = chunk[4] as usize;
            reassembled.extend_from_slice(&chunk[5..5 + lc]);
        }
        assert_eq!(reassembled, ext_body);
    }

    #[test]
    fn get_response_bytes() {
        assert_eq!(get_response(), vec![0x00, 0xC0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn instruction_codes() {
        assert_eq!(Instruction::Select.code(), 0xA4);
        assert_eq!(Instruction::PerformSecurityOperation.code(), 0x2A);
        assert_eq!(Instruction::GenerateAsymmetricKeyPair.code(), 0x46);
    }

    #[test]
    fn slot_key_ref_and_fid_are_distinct_per_slot() {
        let refs: Vec<u8> = Slot::all().iter().map(|s| s.key_ref()).collect();
        assert_eq!(
            refs.len(),
            refs.iter().collect::<std::collections::HashSet<_>>().len()
        );
        let fids: Vec<u16> = Slot::all().iter().map(|s| s.default_cert_fid()).collect();
        assert_eq!(
            fids.len(),
            fids.iter().collect::<std::collections::HashSet<_>>().len()
        );
    }

    #[test]
    fn fid_table_default_matches_slot_defaults() {
        let t = FidTable::default();
        for slot in Slot::all() {
            assert_eq!(t.fid_for(slot), slot.default_cert_fid());
        }
    }

    #[test]
    fn fid_table_override_is_per_slot() {
        let mut t = FidTable::default();
        t.signature = 0xABCD;
        assert_eq!(t.fid_for(Slot::Signature), 0xABCD);
        assert_eq!(
            t.fid_for(Slot::Authentication),
            Slot::Authentication.default_cert_fid()
        );
    }

    #[test]
    fn key_alg_round_trips() {
        for alg in [
            KeyAlg::Rsa2048,
            KeyAlg::Rsa3072,
            KeyAlg::EccP256,
            KeyAlg::EccP384,
        ] {
            assert_eq!(KeyAlg::from_id(alg.id()), Some(alg));
        }
        assert_eq!(KeyAlg::from_id(0xFF), None);
    }

    #[test]
    fn key_alg_to_piv_alg_preserves_shape() {
        assert_eq!(KeyAlg::EccP256.to_piv_alg(), keyroost_piv::KeyAlg::EccP256);
        assert_eq!(KeyAlg::Rsa2048.to_piv_alg(), keyroost_piv::KeyAlg::Rsa2048);
    }

    #[test]
    fn key_alg_from_piv_alg_round_trips() {
        for alg in [
            KeyAlg::Rsa2048,
            KeyAlg::Rsa3072,
            KeyAlg::EccP256,
            KeyAlg::EccP384,
        ] {
            assert_eq!(KeyAlg::from_piv_alg(alg.to_piv_alg()), Some(alg));
        }
        assert_eq!(KeyAlg::from_piv_alg(keyroost_piv::KeyAlg::Ed25519), None);
    }

    #[test]
    fn admin_alg_block_and_key_len() {
        assert_eq!(IasAdminAlg::TripleDes.block_size(), 8);
        assert_eq!(IasAdminAlg::TripleDes.key_len(), 24);
        assert_eq!(IasAdminAlg::Aes128.block_size(), 16);
        assert_eq!(IasAdminAlg::Aes128.key_len(), 16);
    }

    #[test]
    fn read_ber_len_forms() {
        assert_eq!(read_ber_len(&[0x05]), Ok((5, 1)));
        assert_eq!(read_ber_len(&[0x81, 0x80]), Ok((0x80, 2)));
        assert_eq!(read_ber_len(&[0x82, 0x01, 0x02]), Ok((0x0102, 3)));
        assert_eq!(read_ber_len(&[0x80]), Err(ParseError::BadLength));
        assert_eq!(read_ber_len(&[]), Err(ParseError::Truncated));
    }

    #[test]
    fn find_tlv_locates_second_of_two() {
        let buf = [0x80, 0x01, 0xAA, 0x84, 0x01, 0xBB];
        assert_eq!(find_tlv(&buf, 0x84), Some(&[0xBB][..]));
        assert_eq!(find_tlv(&buf, 0x99), None);
    }

    #[test]
    fn find_tlv_never_panics_on_truncated_input() {
        for buf in [&[0x80][..], &[0x80, 0x05][..], &[0x81][..], &[][..]] {
            let _ = find_tlv(buf, 0x80);
        }
    }

    #[test]
    fn parse_generated_public_key_rsa() {
        let buf = [
            0x7F, 0x49, 0x08, 0x81, 0x02, 0xAA, 0xBB, 0x82, 0x02, 0x01, 0x00,
        ];
        match parse_generated_public_key(&buf).unwrap() {
            PublicKey::Rsa { modulus, exponent } => {
                assert_eq!(modulus, vec![0xAA, 0xBB]);
                assert_eq!(exponent, vec![0x01, 0x00]);
            }
            PublicKey::Ecc { .. } => panic!("expected RSA"),
        }
    }

    #[test]
    fn parse_generated_public_key_ecc() {
        let buf = [0x7F, 0x49, 0x06, 0x86, 0x04, 0x04, 0x11, 0x22, 0x33];
        match parse_generated_public_key(&buf).unwrap() {
            PublicKey::Ecc { point } => assert_eq!(point, vec![0x04, 0x11, 0x22, 0x33]),
            PublicKey::Rsa { .. } => panic!("expected ECC"),
        }
    }

    #[test]
    fn parse_generated_public_key_rejects_wrong_tag() {
        assert_eq!(
            parse_generated_public_key(&[0x7F, 0x48, 0x00]),
            Err(ParseError::NotPublicKeyTemplate)
        );
        assert_eq!(
            parse_generated_public_key(&[]),
            Err(ParseError::NotPublicKeyTemplate)
        );
    }
}
