#![no_main]
//! Fuzz the compressed PIV certificate reader: the in-tree gzip (RFC 1952)
//! header walk + CRC-32/ISIZE trailer check around `miniz_oxide`'s capped
//! inflate, and the GET DATA certificate-object decoder that routes a cert
//! flagged gzip (CertInfo bit 0) through it. Both are fed card-supplied
//! bytes, so a hostile or broken card must get an error, never a panic or an
//! unbounded allocation.
//!
//! Properties under fuzz, for ANY input:
//! - neither decoder panics;
//! - inflated output never exceeds `MAX_CERT_DECOMPRESSED` (64 KiB);
//! - decoding is deterministic;
//! - an `Ok` inflate re-decodes consistently: the same bytes re-wrapped in an
//!   independently built (stored-block) gzip stream inflate back to
//!   themselves, and the original stream inside a compressed cert object
//!   decodes to the same result;
//! - the cert-object decoder agrees with its parts: an uncompressed cert is
//!   passed through byte-for-byte, a compressed one is exactly the gzip
//!   reader's result.
use keyroost_transport::fuzzing::{cert_object_der, gunzip_capped, MAX_CERT_DECOMPRESSED};
use libfuzzer_sys::fuzz_target;

/// gzip CRC-32 (reflected, poly 0xEDB88320), bitwise — deliberately not the
/// crate's table-driven one, so the re-wrap check is independent.
fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// `payload` as a minimal gzip stream of stored (uncompressed) DEFLATE blocks.
fn gzip_stored(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
    let mut chunks = payload.chunks(0xFFFF).peekable();
    if chunks.peek().is_none() {
        v.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    }
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        let len = chunk.len() as u16;
        v.push(u8::from(last));
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&(!len).to_le_bytes());
        v.extend_from_slice(chunk);
    }
    v.extend_from_slice(&crc32(payload).to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v
}

/// BER-TLV with a short- or long-form length (inputs stay far below 16 MiB).
fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let n = val.len();
    let mut v = vec![tag];
    match n {
        0..=0x7F => v.push(n as u8),
        0x80..=0xFF => v.extend_from_slice(&[0x81, n as u8]),
        0x100..=0xFFFF => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        _ => v.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
    }
    v.extend_from_slice(val);
    v
}

/// `53 { 70 <payload> 71 01 01 FE 00 }`: a cert object flagged gzip.
fn compressed_cert_object(payload: &[u8]) -> Vec<u8> {
    let mut inner = tlv(0x70, payload);
    inner.extend_from_slice(&[0x71, 0x01, 0x01, 0xFE, 0x00]);
    tlv(0x53, &inner)
}

fuzz_target!(|data: &[u8]| {
    // --- the gzip reader, on the raw input ---------------------------------
    let inflated = gunzip_capped(data);
    assert_eq!(gunzip_capped(data), inflated, "gunzip is not deterministic");
    if let Ok(out) = &inflated {
        assert!(
            out.len() <= MAX_CERT_DECOMPRESSED,
            "inflated {} bytes, past the {MAX_CERT_DECOMPRESSED}-byte cap",
            out.len()
        );
        // Re-decodes consistently: an independent encoding of the output
        // inflates back to exactly the output...
        assert_eq!(gunzip_capped(&gzip_stored(out)).as_ref(), Ok(out));
        // ...and the original stream, as a compressed cert object, yields it.
        assert_eq!(
            cert_object_der(&compressed_cert_object(data)),
            Ok(Some(out.clone()))
        );
    }

    // --- the cert-object decoder, on the raw input -------------------------
    let decoded = cert_object_der(data);
    assert_eq!(
        cert_object_der(data),
        decoded,
        "cert decode is not deterministic"
    );
    let parts = keyroost_piv::unwrap_data_object(data)
        .ok()
        .and_then(keyroost_piv::cert_object_parts);
    match parts {
        None => assert_eq!(decoded, Ok(None), "no `70` cert TLV, yet a cert came back"),
        Some((der, false)) => assert_eq!(decoded, Ok(Some(der.to_vec()))),
        Some((der, true)) => {
            let expected = gunzip_capped(der).map(Some);
            assert_eq!(decoded, expected);
            if let Ok(Some(out)) = &decoded {
                assert!(out.len() <= MAX_CERT_DECOMPRESSED);
            }
        }
    }
});
