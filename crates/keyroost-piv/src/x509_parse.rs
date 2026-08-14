//! Minimal X.509 Subject-DN *reader* (the inverse of the DER builder in
//! [`crate::x509`]).
//!
//! Scope is deliberately tiny: walk an X.509 `Certificate` (RFC 5280) far
//! enough to reach the `subject` `Name` and pull out its RDN attribute/value
//! pairs for human display. It does **not** validate signatures, parse
//! validity, extensions, or the public key — only the Subject DN.
//!
//! No external dependencies (this crate has none and must keep it). The DER
//! reader is a hand-rolled TLV walker that rejects truncated or over-long
//! length fields with an error rather than panicking, so feeding it a random
//! or truncated buffer is safe.
//!
//! # Example
//!
//! ```no_run
//! use keyroost_piv::x509_parse::parse_subject_dn;
//! # let cert_der: &[u8] = &[];
//! if let Ok(dn) = parse_subject_dn(cert_der) {
//!     println!("{dn}"); // e.g. "C=US, O=keyroost, CN=PIV Authentication"
//! }
//! ```

use std::fmt;

use crate::KeyAlg;

/// Errors from reading a Subject DN out of a DER certificate.
#[derive(Debug, PartialEq, Eq)]
pub enum X509ParseError {
    /// A TLV length field ran past the end of the buffer, or the buffer ended
    /// before an expected element.
    Truncated,
    /// A DER length used an unsupported long form (more than 4 length octets)
    /// — far larger than any real certificate.
    LengthTooLarge,
    /// The byte structure didn't match the expected `Certificate` /
    /// `tbsCertificate` / `Name` shape (wrong tag where one was required).
    Malformed,
}

impl fmt::Display for X509ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X509ParseError::Truncated => write!(f, "certificate ended unexpectedly (truncated)"),
            X509ParseError::LengthTooLarge => write!(f, "DER length field is implausibly large"),
            X509ParseError::Malformed => write!(f, "certificate structure did not match X.509"),
        }
    }
}

impl std::error::Error for X509ParseError {}

// ---------------------------------------------------------------------------
// DER TLV reader
// ---------------------------------------------------------------------------

/// One parsed DER element: its tag byte and its content bytes.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Read one DER TLV from the front of `input`, returning the element and the
/// remaining bytes after it. Supports definite short-form and long-form lengths
/// (`0x81`/`0x82`/… up to 4 length octets — certificates routinely exceed 127
/// content bytes). Indefinite length (`0x80`) and over-long lengths are
/// rejected, not panicked on.
fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), X509ParseError> {
    let tag = *input.first().ok_or(X509ParseError::Truncated)?;
    let len_byte = *input.get(1).ok_or(X509ParseError::Truncated)?;

    let (len, header) = if len_byte & 0x80 == 0 {
        // Short form: the byte is the length.
        (len_byte as usize, 2)
    } else {
        let num = (len_byte & 0x7f) as usize;
        // 0x80 is indefinite length (not valid in DER); >4 octets is absurd for
        // a certificate and would risk overflow on 32-bit usize.
        if num == 0 || num > 4 {
            return Err(X509ParseError::LengthTooLarge);
        }
        let mut len = 0usize;
        for i in 0..num {
            let b = *input.get(2 + i).ok_or(X509ParseError::Truncated)?;
            len = (len << 8) | b as usize;
        }
        (len, 2 + num)
    };

    let end = header
        .checked_add(len)
        .ok_or(X509ParseError::LengthTooLarge)?;
    if end > input.len() {
        return Err(X509ParseError::Truncated);
    }
    Ok((
        Tlv {
            tag,
            content: &input[header..end],
        },
        &input[end..],
    ))
}

/// Read one TLV and require its tag to equal `expected`.
fn expect_tag(input: &[u8], expected: u8) -> Result<(Tlv<'_>, &[u8]), X509ParseError> {
    let (tlv, rest) = read_tlv(input)?;
    if tlv.tag != expected {
        return Err(X509ParseError::Malformed);
    }
    Ok((tlv, rest))
}

// ---------------------------------------------------------------------------
// OID decoding
// ---------------------------------------------------------------------------

/// Decode a DER OBJECT IDENTIFIER content (without the tag/length) to its
/// dotted-decimal string. Returns `None` if the encoding is malformed.
fn decode_oid(content: &[u8]) -> Option<String> {
    let mut iter = content.iter();

    // The first sub-identifier is itself base-128 (it may span several bytes),
    // and it encodes both leading arcs (X.690 §8.19): X<40 -> 0.X, X<80 ->
    // 1.(X-40), else 2.(X-80). Decoding only the first *byte* mis-renders any
    // OID whose first sub-identifier doesn't fit in one byte (e.g. 2.999).
    let mut first_sid: u64 = 0;
    let mut got_first = false;
    for &b in iter.by_ref() {
        first_sid = (first_sid << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            got_first = true;
            break;
        }
    }
    if !got_first {
        return None; // empty content, or an unterminated first sub-identifier
    }
    let (arc1, arc2) = if first_sid < 40 {
        (0, first_sid)
    } else if first_sid < 80 {
        (1, first_sid - 40)
    } else {
        (2, first_sid - 80)
    };
    let mut out = format!("{arc1}.{arc2}");

    let mut value: u64 = 0;
    let mut started = false;
    for &b in iter {
        started = true;
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
            started = false;
        }
    }
    // A high-bit-set byte with no terminator is malformed.
    if started {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// DN attribute labels
// ---------------------------------------------------------------------------

/// A directory-name attribute type, mapped to a short label for the common
/// OIDs and falling back to the dotted-decimal OID for anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnAttr {
    /// commonName — `2.5.4.3`
    CommonName,
    /// organizationName — `2.5.4.10`
    Organization,
    /// organizationalUnitName — `2.5.4.11`
    OrganizationalUnit,
    /// countryName — `2.5.4.6`
    Country,
    /// localityName — `2.5.4.7`
    Locality,
    /// stateOrProvinceName — `2.5.4.8`
    StateOrProvince,
    /// serialNumber — `2.5.4.5`
    SerialNumber,
    /// emailAddress (PKCS#9) — `1.2.840.113549.1.9.1`
    EmailAddress,
    /// Any other attribute: the dotted-decimal OID, preserved so it still
    /// renders rather than being dropped.
    Other(String),
}

impl DnAttr {
    /// Map a dotted-decimal OID string to the matching attribute.
    fn from_oid(oid: &str) -> DnAttr {
        match oid {
            "2.5.4.3" => DnAttr::CommonName,
            "2.5.4.10" => DnAttr::Organization,
            "2.5.4.11" => DnAttr::OrganizationalUnit,
            "2.5.4.6" => DnAttr::Country,
            "2.5.4.7" => DnAttr::Locality,
            "2.5.4.8" => DnAttr::StateOrProvince,
            "2.5.4.5" => DnAttr::SerialNumber,
            "1.2.840.113549.1.9.1" => DnAttr::EmailAddress,
            _ => DnAttr::Other(oid.to_string()),
        }
    }

    /// The short label used when rendering this attribute (`CN`, `O`, …), or the
    /// dotted-decimal OID for an unknown attribute.
    pub fn label(&self) -> &str {
        match self {
            DnAttr::CommonName => "CN",
            DnAttr::Organization => "O",
            DnAttr::OrganizationalUnit => "OU",
            DnAttr::Country => "C",
            DnAttr::Locality => "L",
            DnAttr::StateOrProvince => "ST",
            DnAttr::SerialNumber => "serialNumber",
            DnAttr::EmailAddress => "emailAddress",
            DnAttr::Other(oid) => oid,
        }
    }
}

// ---------------------------------------------------------------------------
// Subject DN
// ---------------------------------------------------------------------------

/// A parsed Subject Distinguished Name: its attribute/value pairs in encoding
/// (forward) order. [`fmt::Display`] renders them as `CN=Foo, O=Bar` joined
/// with `, ` — for human display, not RFC 4514 canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDn {
    /// The attribute/value pairs, in the order they appear in the certificate.
    pub rdns: Vec<(DnAttr, String)>,
}

impl fmt::Display for SubjectDn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (attr, value) in &self.rdns {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{}={}", attr.label(), value)?;
        }
        Ok(())
    }
}

/// Decode an `AttributeValue` string into a Rust `String`. PrintableString
/// (0x13), UTF8String (0x0C), and IA5String (0x16) are the common directory
/// string types; all are decoded as UTF-8 (lossy on invalid bytes), and any
/// other string-ish type is treated the same way as a best effort.
fn decode_dn_value(content: &[u8]) -> String {
    String::from_utf8_lossy(content).into_owned()
}

/// Parse the Subject DN out of a DER-encoded X.509 `Certificate`.
///
/// Navigates `Certificate -> tbsCertificate -> subject` per RFC 5280:
/// `tbsCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber INTEGER,
/// signature SEQUENCE, issuer Name, validity SEQUENCE, subject Name, ... }`,
/// where `Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }`.
pub fn parse_subject_dn(cert_der: &[u8]) -> Result<SubjectDn, X509ParseError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (cert, _) = expect_tag(cert_der, 0x30)?;
    // tbsCertificate ::= SEQUENCE { ... }
    let (tbs, _) = expect_tag(cert.content, 0x30)?;
    let mut rest = tbs.content;

    // Optional version [0] (context-specific constructed tag 0xA0): skip it.
    {
        let (peek, after) = read_tlv(rest)?;
        if peek.tag == 0xA0 {
            rest = after;
        }
    }
    // serialNumber INTEGER (0x02)
    let (_, rest) = expect_tag(rest, 0x02)?;
    // signature AlgorithmIdentifier SEQUENCE (0x30)
    let (_, rest) = expect_tag(rest, 0x30)?;
    // issuer Name SEQUENCE (0x30)
    let (_, rest) = expect_tag(rest, 0x30)?;
    // validity SEQUENCE (0x30)
    let (_, rest) = expect_tag(rest, 0x30)?;
    // subject Name SEQUENCE (0x30) — our target.
    let (subject, _) = expect_tag(rest, 0x30)?;

    parse_name(subject.content)
}

/// Parse a `Name` (RDNSequence): SEQUENCE content is a series of SETs, each SET
/// a series of `AttributeTypeAndValue` SEQUENCEs `{ OID, value }`. Attributes
/// are collected in encoding order (across SETs and within each SET).
fn parse_name(mut input: &[u8]) -> Result<SubjectDn, X509ParseError> {
    let mut rdns = Vec::new();
    while !input.is_empty() {
        // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        let (set, after_set) = expect_tag(input, 0x31)?;
        input = after_set;
        let mut atv = set.content;
        while !atv.is_empty() {
            // AttributeTypeAndValue ::= SEQUENCE { type OID, value }
            let (seq, after_seq) = expect_tag(atv, 0x30)?;
            atv = after_seq;
            // type OBJECT IDENTIFIER (0x06)
            let (oid_tlv, after_oid) = expect_tag(seq.content, 0x06)?;
            let oid = decode_oid(oid_tlv.content).ok_or(X509ParseError::Malformed)?;
            // value: a string type (PrintableString / UTF8String / IA5String / …)
            let (val_tlv, _) = read_tlv(after_oid)?;
            let attr = DnAttr::from_oid(&oid);
            rdns.push((attr, decode_dn_value(val_tlv.content)));
        }
    }
    Ok(SubjectDn { rdns })
}

// ---------------------------------------------------------------------------
// Yubico key-policy extension (ATTEST certificates)
// ---------------------------------------------------------------------------

/// Yubico PIV key-policy extension OID `1.3.6.1.4.1.41482.3.8`, as DER OBJECT
/// IDENTIFIER content (tag/length stripped). Carried on a slot's ATTEST
/// certificate; its `extnValue` is exactly 2 raw bytes, `[pin_policy,
/// touch_policy]`, using the same byte values as [`crate::PinPolicy::id`] /
/// [`crate::TouchPolicy::id`] (never/once/always = 1/2/3 for PIN;
/// never/always/cached = 1/2/3 for touch).
const KEY_POLICY_EXT_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08];

/// Parse the PIN/touch policy bytes out of a slot's ATTEST certificate, if the
/// Yubico key-policy extension is present. Returns `Ok(None)` — not an error —
/// when the extension is simply absent: a certificate that predates it, or
/// isn't a Yubico attestation cert at all, is a normal case for a caller that
/// is only using this as a fallback source (GET METADATA firmware < 5.3).
///
/// Navigates `Certificate -> tbsCertificate -> extensions` per RFC 5280,
/// continuing past where [`parse_subject_dn`] stops: `subject Name,
/// subjectPublicKeyInfo SEQUENCE, issuerUniqueID [1] OPTIONAL, subjectUniqueID
/// [2] OPTIONAL, extensions [3] EXPLICIT SEQUENCE OF Extension OPTIONAL`.
pub fn parse_key_policy_extension(cert_der: &[u8]) -> Result<Option<(u8, u8)>, X509ParseError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (cert, _) = expect_tag(cert_der, 0x30)?;
    // tbsCertificate ::= SEQUENCE { ... }
    let (tbs, _) = expect_tag(cert.content, 0x30)?;
    let mut rest = tbs.content;

    // Optional version [0] (context-specific constructed tag 0xA0): skip it.
    {
        let (peek, after) = read_tlv(rest)?;
        if peek.tag == 0xA0 {
            rest = after;
        }
    }
    // serialNumber INTEGER, signature SEQUENCE, issuer Name, validity SEQUENCE,
    // subject Name, subjectPublicKeyInfo SEQUENCE: skip each in turn.
    let (_, rest) = expect_tag(rest, 0x02)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    let (_, mut rest) = expect_tag(rest, 0x30)?;

    // issuerUniqueID [1] (0x81) / subjectUniqueID [2] (0x82) are optional and,
    // if present, precede extensions [3] (0xA3). Anything else here (nothing
    // left, or a tag that isn't one of these three) means no extensions block
    // — a normal, not malformed, shape for an older or non-Yubico cert.
    loop {
        if rest.is_empty() {
            return Ok(None);
        }
        let (peek, after) = read_tlv(rest)?;
        match peek.tag {
            0x81 | 0x82 => rest = after,
            0xA3 => {
                // extensions [3] EXPLICIT SEQUENCE OF Extension
                let (exts, _) = expect_tag(peek.content, 0x30)?;
                return find_key_policy(exts.content);
            }
            _ => return Ok(None),
        }
    }
}

/// Scan a `SEQUENCE OF Extension` for the Yubico key-policy extension and
/// return its 2 policy bytes, if found.
fn find_key_policy(mut input: &[u8]) -> Result<Option<(u8, u8)>, X509ParseError> {
    while !input.is_empty() {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
        let (seq, after_seq) = expect_tag(input, 0x30)?;
        input = after_seq;
        let (oid_tlv, after_oid) = expect_tag(seq.content, 0x06)?;
        // Optional `critical` BOOLEAN (0x01): skip if present.
        let after_oid = match read_tlv(after_oid) {
            Ok((peek, after)) if peek.tag == 0x01 => after,
            _ => after_oid,
        };
        let (val_tlv, _) = expect_tag(after_oid, 0x04)?;
        if oid_tlv.content == KEY_POLICY_EXT_OID {
            return match val_tlv.content {
                [pin, touch] => Ok(Some((*pin, *touch))),
                _ => Err(X509ParseError::Malformed),
            };
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// subjectPublicKeyInfo key algorithm
// ---------------------------------------------------------------------------

// Pre-encoded OBJECT IDENTIFIER *content* (tag/length stripped), matching the
// OIDs [`crate::spki::subject_public_key_info`] writes — this is that
// encoder's inverse, read back off a certificate rather than a card response.
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_X25519: &[u8] = &[0x2B, 0x65, 0x6E];

/// Read the key algorithm out of a certificate's `subjectPublicKeyInfo`, for
/// PIV cards that don't answer GET METADATA (pre-5.3 firmware, or a
/// non-Yubico card): the certificate stored in the slot was built (or
/// imported) over the same key, so its own SPKI is a reliable fallback source
/// for the algorithm shown in the slot state line.
///
/// Navigates `Certificate -> tbsCertificate -> subjectPublicKeyInfo` per RFC
/// 5280, continuing past where [`parse_subject_dn`] stops. Returns `Ok(None)`
/// — not an error — for an SPKI algorithm this crate has no [`KeyAlg`]
/// variant for (an unusual curve, an RSA modulus that isn't one of the four
/// PIV sizes): this is a display-only fallback, so "can't tell" is a normal
/// outcome, not a malformed certificate.
pub fn parse_spki_key_alg(cert_der: &[u8]) -> Result<Option<KeyAlg>, X509ParseError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (cert, _) = expect_tag(cert_der, 0x30)?;
    // tbsCertificate ::= SEQUENCE { ... }
    let (tbs, _) = expect_tag(cert.content, 0x30)?;
    let mut rest = tbs.content;

    // Optional version [0] (context-specific constructed tag 0xA0): skip it.
    {
        let (peek, after) = read_tlv(rest)?;
        if peek.tag == 0xA0 {
            rest = after;
        }
    }
    // serialNumber INTEGER, signature SEQUENCE, issuer Name, validity
    // SEQUENCE, subject Name: skip each in turn.
    let (_, rest) = expect_tag(rest, 0x02)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    let (_, rest) = expect_tag(rest, 0x30)?;
    // subjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    let (spki, _) = expect_tag(rest, 0x30)?;
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    let (alg_id, spk_rest) = expect_tag(spki.content, 0x30)?;
    let (oid_tlv, params) = expect_tag(alg_id.content, 0x06)?;

    match oid_tlv.content {
        OID_RSA_ENCRYPTION => rsa_key_size(spk_rest),
        OID_EC_PUBLIC_KEY => {
            // parameters is the namedCurve OID for a NIST curve.
            let (curve, _) = expect_tag(params, 0x06)?;
            Ok(match curve.content {
                OID_P256 => Some(KeyAlg::EccP256),
                OID_P384 => Some(KeyAlg::EccP384),
                _ => None,
            })
        }
        OID_ED25519 => Ok(Some(KeyAlg::Ed25519)),
        OID_X25519 => Ok(Some(KeyAlg::X25519)),
        _ => Ok(None),
    }
}

/// Recover the PIV RSA [`KeyAlg`] (1024/2048/3072/4096) from the modulus size
/// in an SPKI's `subjectPublicKey` BIT STRING, which wraps `RSAPublicKey ::=
/// SEQUENCE { modulus INTEGER, publicExponent INTEGER }`. `None` for a
/// modulus that isn't one of PIV's four sizes.
fn rsa_key_size(bitstring_and_after: &[u8]) -> Result<Option<KeyAlg>, X509ParseError> {
    let (bitstr, _) = expect_tag(bitstring_and_after, 0x03)?;
    // First content byte is the unused-bits count (0 for a byte-aligned DER
    // encoding, which an RSAPublicKey SEQUENCE always is).
    let inner = bitstr.content.get(1..).ok_or(X509ParseError::Truncated)?;
    let (rsa_pub, _) = expect_tag(inner, 0x30)?;
    let (modulus, _) = expect_tag(rsa_pub.content, 0x02)?;
    // Strip the sign-guard `0x00` prefix (present whenever the modulus's top
    // bit is set, i.e. almost always) before sizing.
    let bytes = modulus.content.len() - modulus.content.iter().take_while(|&&b| b == 0).count();
    Ok(match bytes {
        128 => Some(KeyAlg::Rsa1024),
        256 => Some(KeyAlg::Rsa2048),
        384 => Some(KeyAlg::Rsa3072),
        512 => Some(KeyAlg::Rsa4096),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_decoder_common_values() {
        // 2.5.4.3 = 55 04 03
        assert_eq!(decode_oid(&[0x55, 0x04, 0x03]).as_deref(), Some("2.5.4.3"));
        // 1.2.840.113549.1.9.1 = 2A 86 48 86 F7 0D 01 09 01
        assert_eq!(
            decode_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01]).as_deref(),
            Some("1.2.840.113549.1.9.1")
        );
        // UID = 0.9.2342.19200300.100.1.1
        assert_eq!(
            decode_oid(&[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01]).as_deref(),
            Some("0.9.2342.19200300.100.1.1")
        );
    }

    #[test]
    fn oid_decoder_rejects_unterminated() {
        // Trailing byte with the high bit set and no terminator.
        assert_eq!(decode_oid(&[0x55, 0x81]), None);
    }

    #[test]
    fn oid_decoder_multibyte_first_subidentifier() {
        // 2.999: first sub-id = 2*40 + 999 = 1079, encoded multi-byte as 88 37.
        // A naive first/40, first%40 split would give "3.16.55".
        assert_eq!(decode_oid(&[0x88, 0x37]).as_deref(), Some("2.999"));
        // 2.100.3: first sub-id 180 = 81 34, then arc 3.
        assert_eq!(decode_oid(&[0x81, 0x34, 0x03]).as_deref(), Some("2.100.3"));
    }

    #[test]
    fn tlv_long_form_length() {
        // Tag 0x04, long-form length 0x81 0x80 (128), 128 content bytes.
        let mut buf = vec![0x04, 0x81, 0x80];
        buf.extend(std::iter::repeat_n(0xAB, 128));
        let (tlv, rest) = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.content.len(), 128);
        assert!(rest.is_empty());
    }

    #[test]
    fn tlv_long_form_length_two_and_three_octets() {
        // 0x82 form: 2 length octets encoding 0x0140 = 320 content bytes.
        let mut buf = vec![0x04, 0x82, 0x01, 0x40];
        buf.extend(std::iter::repeat_n(0xCD, 320));
        let (tlv, rest) = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.content.len(), 320);
        assert!(rest.is_empty());

        // 0x83 form: 3 length octets encoding 0x010000 = 65536 content bytes.
        let mut buf = vec![0x04, 0x83, 0x01, 0x00, 0x00];
        buf.extend(std::iter::repeat_n(0xEF, 65536));
        let (tlv, rest) = read_tlv(&buf).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.content.len(), 65536);
        assert!(rest.is_empty());
    }

    #[test]
    fn tlv_rejects_five_octet_length() {
        // 0x85 announces 5 length octets — beyond the 4-octet cap. Must Err
        // (LengthTooLarge), not panic, even though no length octets follow.
        assert_eq!(
            read_tlv(&[0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01]).err(),
            Some(X509ParseError::LengthTooLarge)
        );
        // 0x8F (15 octets) likewise.
        assert_eq!(
            read_tlv(&[0x30, 0x8F]).err(),
            Some(X509ParseError::LengthTooLarge)
        );
    }

    #[test]
    fn parse_subject_dn_rejects_unterminated_oid() {
        // Hand-built minimal Certificate whose subject contains an attribute OID
        // whose final byte has the high bit set with no terminator — malformed.
        // Build inner -> outer so lengths stay short-form (all < 128).
        //
        // AttributeTypeAndValue ::= SEQUENCE { OID (bad), value }
        // OID content: 0x55 0x81  (0x81 continues but nothing follows -> malformed)
        let oid = [0x06u8, 0x02, 0x55, 0x81]; // OBJECT IDENTIFIER, len 2
        let value = [0x13u8, 0x01, b'X']; // PrintableString "X"
        let mut atv_content = Vec::new();
        atv_content.extend_from_slice(&oid);
        atv_content.extend_from_slice(&value);
        let mut atv = vec![0x30, atv_content.len() as u8]; // SEQUENCE
        atv.extend_from_slice(&atv_content);

        let mut set = vec![0x31, atv.len() as u8]; // SET
        set.extend_from_slice(&atv);

        // subject Name ::= SEQUENCE OF SET
        let mut subject = vec![0x30, set.len() as u8];
        subject.extend_from_slice(&set);

        // tbsCertificate fields that parse_subject_dn walks before `subject`:
        // serialNumber INTEGER, signature SEQUENCE, issuer SEQUENCE, validity SEQUENCE.
        let serial = [0x02u8, 0x01, 0x01]; // INTEGER 1
        let sig_alg = [0x30u8, 0x00]; // empty SEQUENCE
        let issuer = [0x30u8, 0x00]; // empty Name SEQUENCE
        let validity = [0x30u8, 0x00]; // empty SEQUENCE

        let mut tbs_content = Vec::new();
        tbs_content.extend_from_slice(&serial);
        tbs_content.extend_from_slice(&sig_alg);
        tbs_content.extend_from_slice(&issuer);
        tbs_content.extend_from_slice(&validity);
        tbs_content.extend_from_slice(&subject);
        let mut tbs = vec![0x30, tbs_content.len() as u8];
        tbs.extend_from_slice(&tbs_content);

        // Certificate ::= SEQUENCE { tbsCertificate, ... } — only tbs is read.
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);

        assert_eq!(
            parse_subject_dn(&cert),
            Err(X509ParseError::Malformed),
            "unterminated OID in subject must be rejected as Malformed"
        );
    }

    #[test]
    fn tlv_rejects_truncated_and_indefinite() {
        assert_eq!(read_tlv(&[]).err(), Some(X509ParseError::Truncated));
        assert_eq!(read_tlv(&[0x30]).err(), Some(X509ParseError::Truncated));
        // Declared length 5 but only 2 content bytes present.
        assert_eq!(
            read_tlv(&[0x04, 0x05, 0x00, 0x01]).err(),
            Some(X509ParseError::Truncated)
        );
        // Indefinite length 0x80.
        assert_eq!(
            read_tlv(&[0x30, 0x80]).err(),
            Some(X509ParseError::LengthTooLarge)
        );
    }

    /// Build a minimal-but-well-formed `Certificate` DER, with an optional
    /// `extensions [3]` field containing the given already-DER-encoded
    /// `Extension` SEQUENCEs. Every field before `extensions` is an empty
    /// placeholder (`parse_key_policy_extension` only needs to walk past
    /// them, not read them), so lengths stay in short form throughout.
    fn build_cert(extension_seqs: &[Vec<u8>]) -> Vec<u8> {
        let serial = [0x02u8, 0x01, 0x01]; // INTEGER 1
        let sig_alg = [0x30u8, 0x00]; // empty SEQUENCE
        let issuer = [0x30u8, 0x00]; // empty Name SEQUENCE
        let validity = [0x30u8, 0x00]; // empty SEQUENCE
        let subject = [0x30u8, 0x00]; // empty Name SEQUENCE
        let spki = [0x30u8, 0x00]; // empty SubjectPublicKeyInfo SEQUENCE

        let mut tbs_content = Vec::new();
        tbs_content.extend_from_slice(&serial);
        tbs_content.extend_from_slice(&sig_alg);
        tbs_content.extend_from_slice(&issuer);
        tbs_content.extend_from_slice(&validity);
        tbs_content.extend_from_slice(&subject);
        tbs_content.extend_from_slice(&spki);

        if !extension_seqs.is_empty() {
            let exts_content: Vec<u8> = extension_seqs.iter().flatten().copied().collect();
            let mut exts_seq = vec![0x30, exts_content.len() as u8];
            exts_seq.extend_from_slice(&exts_content);
            tbs_content.push(0xA3); // extensions [3] EXPLICIT
            tbs_content.push(exts_seq.len() as u8);
            tbs_content.extend_from_slice(&exts_seq);
        }

        let mut tbs = vec![0x30, tbs_content.len() as u8];
        tbs.extend_from_slice(&tbs_content);
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);
        cert
    }

    /// Like [`build_cert`] but with a real `subjectPublicKeyInfo` in place of
    /// the empty placeholder, for [`parse_spki_key_alg`] tests. Lengths can
    /// exceed short form once a real SPKI is in play (an RSA-4096 SPKI is
    /// well over 127 bytes), so this reuses [`crate::spki`]'s own DER
    /// primitives rather than the single-byte lengths `build_cert` gets away
    /// with.
    fn build_cert_with_spki(spki: &[u8]) -> Vec<u8> {
        use crate::spki::{der_seq, der_tlv};

        let serial = der_tlv(0x02, &[0x01]); // INTEGER 1
        let sig_alg = der_seq(&[]); // empty SEQUENCE
        let issuer = der_seq(&[]); // empty Name SEQUENCE
        let validity = der_seq(&[]); // empty SEQUENCE
        let subject = der_seq(&[]); // empty Name SEQUENCE

        let tbs = der_seq(&[&serial, &sig_alg, &issuer, &validity, &subject, spki]);
        der_seq(&[&tbs])
    }

    /// `Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING }`
    /// (`critical` omitted — it's DEFAULT FALSE and optional).
    fn build_extension(oid_content: &[u8], value: &[u8]) -> Vec<u8> {
        let mut oid = vec![0x06, oid_content.len() as u8];
        oid.extend_from_slice(oid_content);
        let mut octets = vec![0x04, value.len() as u8];
        octets.extend_from_slice(value);
        let mut content = oid;
        content.extend_from_slice(&octets);
        let mut seq = vec![0x30, content.len() as u8];
        seq.extend_from_slice(&content);
        seq
    }

    #[test]
    fn key_policy_extension_absent_is_none_not_an_error() {
        // No extensions field at all (older/non-attestation cert shape).
        assert_eq!(parse_key_policy_extension(&build_cert(&[])), Ok(None));
    }

    #[test]
    fn key_policy_extension_ignores_unrelated_extensions() {
        let other = build_extension(&[0x55, 0x1D, 0x0F], &[0x03, 0x02, 0x05, 0xA0]); // keyUsage, unrelated
        assert_eq!(parse_key_policy_extension(&build_cert(&[other])), Ok(None));
    }

    #[test]
    fn key_policy_extension_decodes_pin_and_touch_bytes() {
        // PinPolicy::Always (0x03), TouchPolicy::Never (0x01).
        let policy_ext = build_extension(KEY_POLICY_EXT_OID, &[0x03, 0x01]);
        let other = build_extension(&[0x55, 0x1D, 0x0F], &[0x03, 0x02, 0x05, 0xA0]);
        assert_eq!(
            parse_key_policy_extension(&build_cert(&[other, policy_ext])),
            Ok(Some((0x03, 0x01)))
        );
    }

    #[test]
    fn key_policy_extension_rejects_wrong_length_value() {
        // A key-policy extension whose value isn't exactly 2 bytes is
        // malformed, not merely "policy unknown" — this OID is only ever
        // meant to carry 2 bytes, so anything else is a corrupt certificate.
        let bad = build_extension(KEY_POLICY_EXT_OID, &[0x03]);
        assert_eq!(
            parse_key_policy_extension(&build_cert(&[bad])),
            Err(X509ParseError::Malformed)
        );
    }

    #[test]
    fn key_policy_extension_survives_critical_flag() {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN TRUE, extnValue OCTET STRING }
        let mut content = vec![0x06, KEY_POLICY_EXT_OID.len() as u8];
        content.extend_from_slice(KEY_POLICY_EXT_OID);
        content.extend_from_slice(&[0x01, 0x01, 0xFF]); // BOOLEAN TRUE
        content.extend_from_slice(&[0x04, 0x02, 0x02, 0x03]); // OCTET STRING [once, cached]
        let mut seq = vec![0x30, content.len() as u8];
        seq.extend_from_slice(&content);
        assert_eq!(
            parse_key_policy_extension(&build_cert(&[seq])),
            Ok(Some((0x02, 0x03)))
        );
    }

    #[test]
    fn spki_key_alg_round_trips_every_piv_algorithm() {
        // Each `KeyAlg` fed through the real encoder (`subject_public_key_info`)
        // must come back out of `parse_spki_key_alg` unchanged — the fallback
        // path this exercises has to agree with what a card/cert actually
        // carries, not just with a hand-built fixture.
        let ecc_point = {
            let mut p = vec![0x04];
            p.extend(std::iter::repeat_n(0xAB, 64));
            p
        };
        let eddsa_point = vec![0x11u8; 32];
        let cases = [
            (
                KeyAlg::Rsa1024,
                crate::PublicKey::Rsa {
                    modulus: vec![0xFFu8; 128],
                    exponent: vec![0x01, 0x00, 0x01],
                },
            ),
            (
                KeyAlg::Rsa2048,
                crate::PublicKey::Rsa {
                    modulus: vec![0xFFu8; 256],
                    exponent: vec![0x01, 0x00, 0x01],
                },
            ),
            (
                KeyAlg::Rsa3072,
                crate::PublicKey::Rsa {
                    modulus: vec![0xFFu8; 384],
                    exponent: vec![0x01, 0x00, 0x01],
                },
            ),
            (
                KeyAlg::Rsa4096,
                crate::PublicKey::Rsa {
                    modulus: vec![0xFFu8; 512],
                    exponent: vec![0x01, 0x00, 0x01],
                },
            ),
            (
                KeyAlg::EccP256,
                crate::PublicKey::Ecc {
                    point: ecc_point.clone(),
                },
            ),
            (
                KeyAlg::EccP384,
                crate::PublicKey::Ecc {
                    point: ecc_point.clone(),
                },
            ),
            (
                KeyAlg::Ed25519,
                crate::PublicKey::Ecc {
                    point: eddsa_point.clone(),
                },
            ),
            (KeyAlg::X25519, crate::PublicKey::Ecc { point: eddsa_point }),
        ];
        for (alg, key) in cases {
            let spki = crate::spki::subject_public_key_info(&key, alg).unwrap();
            let cert = build_cert_with_spki(&spki);
            assert_eq!(
                parse_spki_key_alg(&cert),
                Ok(Some(alg)),
                "algorithm {alg:?} did not round-trip"
            );
        }
    }

    #[test]
    fn spki_key_alg_rsa_modulus_with_high_bit_set_still_sizes_correctly() {
        // A modulus whose top bit is set gets a DER sign-guard `0x00` prefix,
        // one byte longer than the "raw" key size — the size calc must strip
        // that prefix, not count it.
        let key = crate::PublicKey::Rsa {
            modulus: {
                let mut m = vec![0xFFu8; 256]; // top bit set -> DER prefixes 0x00
                m[0] = 0xFF;
                m
            },
            exponent: vec![0x01, 0x00, 0x01],
        };
        let spki = crate::spki::subject_public_key_info(&key, KeyAlg::Rsa2048).unwrap();
        let cert = build_cert_with_spki(&spki);
        assert_eq!(parse_spki_key_alg(&cert), Ok(Some(KeyAlg::Rsa2048)));
    }

    #[test]
    fn spki_key_alg_unrecognized_oid_is_none_not_an_error() {
        use crate::spki::{der_seq, der_tlv};
        // e.g. DSA (1.2.840.10040.4.1) — not a PIV algorithm, so this must
        // degrade to "can't tell", not fail the whole read.
        let dsa_oid = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01]);
        let alg_id = der_seq(&[&dsa_oid]);
        let spk = der_seq(&[&alg_id, &[0x03, 0x01, 0x00]]); // dummy empty BIT STRING
        let cert = build_cert_with_spki(&spk);
        assert_eq!(parse_spki_key_alg(&cert), Ok(None));
    }

    #[test]
    fn spki_key_alg_ec_unrecognized_curve_is_none() {
        use crate::spki::{der_seq, der_tlv};
        // secp256k1 (1.3.132.0.10) — a real EC curve, but not one PIV supports.
        let secp256k1 = [0x2B, 0x81, 0x04, 0x00, 0x0A];
        let alg_id = der_seq(&[
            &der_tlv(0x06, OID_EC_PUBLIC_KEY),
            &der_tlv(0x06, &secp256k1),
        ]);
        let spk = der_seq(&[&alg_id, &[0x03, 0x02, 0x00, 0x04]]);
        let cert = build_cert_with_spki(&spk);
        assert_eq!(parse_spki_key_alg(&cert), Ok(None));
    }
}
