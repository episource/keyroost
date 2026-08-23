//! ISO 7816-4 APDU construction and the per-command MAC the Molto2 expects.
//!
//! Wire format reference (derived from observing molto2.py against a real device):
//!
//!   CLA  INS  P1   P2   Lc   data...
//!
//! For "secure" commands (CLA 0x84) the trailing 4 bytes of `data` are a MAC over
//! `[CLA, INS, P1, P2, Lc-as-1-byte-payload-len, payload]` computed as
//! SM4-CBC(key=SHA1(customer_key)[..16], iv=0) with 80/00 padding, taking the
//! last block then keeping its first 4 bytes.

use crate::sm4::Sm4;

pub const CLA_PLAIN: u8 = 0x80;
pub const CLA_SECURE: u8 = 0x84;

/// SM4 block-size padding (ISO/IEC 9797-1 padding method 2): append 0x80 then
/// zeros up to a 16-byte boundary. If the input is already block-aligned, an
/// entire extra padding block is appended.
pub fn pad_iso7816(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

/// SM4 padding *only when necessary*: append 0x80 then zeros up to the next
/// 16-byte boundary; if already aligned, do nothing. This matches molto2.py's
/// behaviour for seed/title payloads.
pub fn pad_iso7816_minimal(data: &[u8]) -> Vec<u8> {
    if data.len() % 16 == 0 {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(((data.len() / 16) + 1) * 16);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

/// Compute the 4-byte MAC the Molto2 expects on CLA 0x84 commands.
///
/// `header` is the 5-byte APDU prefix used as the MAC AAD: `[CLA, INS, P1, P2, Lc]`
/// where `Lc` here is the *payload* length (without the MAC), not the final
/// APDU Lc. `payload` is the encrypted body without the MAC suffix.
pub fn mac(sm4_key: &[u8; 16], header: &[u8; 5], payload: &[u8]) -> [u8; 4] {
    let mut msg = Vec::with_capacity(header.len() + payload.len() + 16);
    msg.extend_from_slice(header);
    msg.extend_from_slice(payload);
    let padded = pad_iso7816_minimal(&msg);
    let mut buf = padded;
    let cipher = Sm4::new(sm4_key);
    let iv = [0u8; 16];
    cipher.encrypt_cbc(&iv, &mut buf);
    // Take the last block, keep its first 4 bytes.
    let last = &buf[buf.len() - 16..];
    [last[0], last[1], last[2], last[3]]
}

/// Error from [`try_build_apdu`]: the body exceeds the 255-byte case-3
/// short-APDU limit, so no valid 1-byte `Lc` exists for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApduBodyTooLong {
    /// The offending body length in bytes.
    pub len: usize,
}

impl core::fmt::Display for ApduBodyTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "APDU body is {} bytes; a case-3 short APDU holds at most 255",
            self.len
        )
    }
}

impl std::error::Error for ApduBodyTooLong {}

/// Build a case-3 short APDU (header + Lc + data, no Le), rejecting a body
/// past the 255-byte limit instead of panicking. Use this for bodies whose
/// length a caller or a device can influence.
pub fn try_build_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<Vec<u8>, ApduBodyTooLong> {
    if data.len() > 255 {
        return Err(ApduBodyTooLong { len: data.len() });
    }
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(cla);
    out.push(ins);
    out.push(p1);
    out.push(p2);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    Ok(out)
}

/// Build a case-3 short APDU (header + Lc + data, no Le).
///
/// # Panics
/// Panics if `data` exceeds 255 bytes. Fine for the fixed-size Molto2
/// command bodies in `commands.rs`; anything caller- or device-sized goes
/// through [`try_build_apdu`].
pub fn build_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    match try_build_apdu(cla, ins, p1, p2, data) {
        Ok(apdu) => apdu,
        Err(e) => panic!("short APDU body too large: {} bytes", e.len),
    }
}

/// Build a case-2 short APDU (header + Le only). `le` of 0 means "up to 256 bytes".
pub fn build_apdu_get(cla: u8, ins: u8, p1: u8, p2: u8, le: u8) -> Vec<u8> {
    vec![cla, ins, p1, p2, le]
}

/// Build the APDU to resend after a `6C xx` ("wrong Le") status word.
///
/// ISO 7816-4: `6C xx` tells the host to reissue the *same* command with
/// `Le = xx`. Where that Le goes depends on the case of the original APDU:
///
/// * case 1 (bare 4-byte header): **append** Le → case 2;
/// * case 2 (header + Le): **replace** the trailing Le byte — appending
///   would produce the malformed `… Le_old Le_new`;
/// * case 3 (header + Lc + data, no Le): **append** Le → case 4. The last
///   byte here is *data* and must never be overwritten;
/// * case 4 (header + Lc + data + Le): **replace** the trailing Le byte.
///
/// Classification is by structure, not length: only an APDU that provably
/// ends in Le gets its last byte replaced. An extended-form APDU
/// (`Lc = 00 hi lo`) never matches the case-4 length check and safely falls
/// through to append.
pub fn resend_with_le(original: &[u8], le: u8) -> Vec<u8> {
    let mut out = original.to_vec();
    let ends_in_le = match out.len() {
        0..=4 => false, // case 1 (or truncated): nothing to replace
        5 => true,      // case 2: the 5th byte is Le
        n => {
            // Short-form body APDU: header + Lc + `Lc` data bytes (case 3),
            // or the same plus one trailing Le (case 4).
            let lc = out[4] as usize;
            n == 5 + lc + 1
        }
    };
    if ends_in_le {
        *out.last_mut().unwrap() = le;
    } else {
        out.push(le);
    }
    out
}

/// Append a BER-TLV length: short form under 0x80, else `0x81 len` (1-byte
/// long form) or `0x82 len_hi len_lo` (2-byte long form). Shared by every
/// TLV-based card protocol in this workspace (PIV, IAS, and friends) — not
/// specific to any one of them.
pub fn push_ber_len(out: &mut Vec<u8>, len: usize) {
    assert!(len <= 0xFFFF, "BER-TLV value too large");
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Append a TLV: `tag || ber_len(value) || value`.
pub fn push_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    out.extend_from_slice(tag);
    push_ber_len(out, value.len());
    out.extend_from_slice(value);
}

/// Build a case-3/case-4 APDU, choosing short or extended-length encoding by
/// body size. `le` requests a response (`Some(0)` = "up to 65536" in extended
/// form, 256 in short form). Extended-length APDUs are widely accepted over
/// CCID; bodies over 255 bytes (certificate import, RSA signing input) need
/// them on every card protocol this workspace speaks.
pub fn build_apdu_ext(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u16>) -> Vec<u8> {
    assert!(data.len() <= 0xFFFF, "extended APDU body too large");
    if data.len() <= 255 && le.is_none_or(|v| v <= 256) {
        // Short form. Le==256 is encoded as the single byte 0x00.
        let mut out = Vec::with_capacity(6 + data.len());
        out.extend_from_slice(&[cla, ins, p1, p2]);
        if !data.is_empty() {
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
        if let Some(le) = le {
            out.push(if le == 256 { 0x00 } else { le as u8 });
        }
        return out;
    }
    // Extended form: a leading 0x00 marker, then 2-byte Lc and/or 2-byte Le.
    let mut out = Vec::with_capacity(9 + data.len());
    out.extend_from_slice(&[cla, ins, p1, p2, 0x00]);
    if !data.is_empty() {
        out.push((data.len() >> 8) as u8);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if let Some(le) = le {
        // 0 → 0x0000 meaning 65536.
        out.push((le >> 8) as u8);
        out.push(le as u8);
    }
    out
}

/// Split `data` into an ISO 7816-4 command-chaining sequence: every chunk but
/// the last carries the chaining class bit (`CLA` `0x10`), the final chunk
/// clears it and (if `final_le` is given) appends a one-byte short-form `Le`.
/// Each chunk is a case-3/case-4 APDU `cla[|0x10] ins p1 p2 Lc <chunk> [Le]`
/// with a plain one-byte `Lc` — chaining links are always short-form, that's
/// the whole point of the fallback. The card reassembles the chunks into one
/// logical command whose data field is byte-identical to what a single
/// extended-length APDU ([`build_apdu_ext`]) would have carried.
///
/// This is the fallback for cards/readers that reject a single extended-`Lc`
/// APDU outright but parse ISO 7816-4 chaining fine.
///
/// # Panics
/// Panics if `max_chunk` is 0 or greater than 255 (a single-byte `Lc` can't
/// exceed 255).
pub fn chain_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    max_chunk: usize,
    final_le: Option<u8>,
) -> Vec<Vec<u8>> {
    assert!(
        (1..=255).contains(&max_chunk),
        "command-chaining chunk size must be 1..=255"
    );
    if data.is_empty() {
        let mut apdu = vec![cla, ins, p1, p2, 0x00];
        if let Some(le) = final_le {
            apdu.push(le);
        }
        return vec![apdu];
    }
    let chunks: Vec<&[u8]> = data.chunks(max_chunk).collect();
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let chained_cla = if i < last { cla | 0x10 } else { cla };
            let mut apdu = Vec::with_capacity(5 + chunk.len() + 1);
            apdu.extend_from_slice(&[chained_cla, ins, p1, p2, chunk.len() as u8]);
            apdu.extend_from_slice(chunk);
            if i == last {
                if let Some(le) = final_le {
                    apdu.push(le);
                }
            }
            apdu
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_block_aligned_minimal_is_noop() {
        let data = [0xaa; 16];
        assert_eq!(pad_iso7816_minimal(&data).as_slice(), &data);
    }

    #[test]
    fn padding_full_form_always_pads() {
        let data = [0xaa; 16];
        let padded = pad_iso7816(&data);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[16], 0x80);
        assert!(padded[17..].iter().all(|&b| b == 0));
    }

    #[test]
    fn padding_unaligned() {
        let data = b"hello"; // 5 bytes
        let padded = pad_iso7816_minimal(data);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..5], b"hello");
        assert_eq!(padded[5], 0x80);
        assert!(padded[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn build_apdu_layout() {
        let apdu = build_apdu(0x84, 0xC5, 0x01, 0x02, &[0xde, 0xad]);
        assert_eq!(apdu, [0x84, 0xC5, 0x01, 0x02, 0x02, 0xde, 0xad]);
    }

    #[test]
    fn resend_with_le_covers_all_four_short_cases() {
        // Case 1 (bare header): append Le → case 2.
        assert_eq!(
            resend_with_le(&[0x80, 0xC5, 0x05, 0x02], 0x00),
            vec![0x80, 0xC5, 0x05, 0x02, 0x00]
        );
        // Case 2 (header + Le): replace the trailing Le.
        assert_eq!(
            resend_with_le(&[0x00, 0xC0, 0x00, 0x00, 0x20], 0x08),
            vec![0x00, 0xC0, 0x00, 0x00, 0x08]
        );
        // Case 3 (header + Lc + data): append; the last data byte survives.
        let apdu = build_apdu(0x80, 0xC5, 0x05, 0x02, &[0xAA; 16]);
        let mut expected = apdu.clone();
        expected.push(0x2A);
        assert_eq!(resend_with_le(&apdu, 0x2A), expected);
        // Case 4 (header + Lc + data + Le): replace the trailing Le.
        assert_eq!(
            resend_with_le(&[0x80, 0xC5, 0x05, 0x00, 0x02, 0x03, 0x07, 0x10], 0x40),
            vec![0x80, 0xC5, 0x05, 0x00, 0x02, 0x03, 0x07, 0x40]
        );
    }

    #[test]
    fn try_build_apdu_boundary() {
        // At the exact 255-byte case-3 limit the APDU builds; one byte over
        // is a typed error, not a panic (device/caller-length safety).
        let body = [0u8; 255];
        let apdu = try_build_apdu(0x00, 0xA2, 0x00, 0x01, &body).unwrap();
        assert_eq!(apdu.len(), 5 + 255);
        assert_eq!(apdu[4], 255);
        let over = [0u8; 256];
        assert_eq!(
            try_build_apdu(0x00, 0xA2, 0x00, 0x01, &over),
            Err(ApduBodyTooLong { len: 256 })
        );
    }

    #[test]
    fn ber_len_forms() {
        let mut short = Vec::new();
        push_ber_len(&mut short, 0x7F);
        assert_eq!(short, vec![0x7F]);

        let mut long1 = Vec::new();
        push_ber_len(&mut long1, 0x80);
        assert_eq!(long1, vec![0x81, 0x80]);

        let mut long2 = Vec::new();
        push_ber_len(&mut long2, 0x0102);
        assert_eq!(long2, vec![0x82, 0x01, 0x02]);
    }

    #[test]
    fn push_tlv_layout() {
        let mut out = Vec::new();
        push_tlv(&mut out, &[0x7C], &[0xAA, 0xBB]);
        assert_eq!(out, vec![0x7C, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn build_apdu_ext_short_form_under_255() {
        let apdu = build_apdu_ext(0x00, 0x47, 0x00, 0x9A, &[0x80, 0x01, 0x11], Some(0));
        assert_eq!(
            apdu,
            vec![0x00, 0x47, 0x00, 0x9A, 0x03, 0x80, 0x01, 0x11, 0x00]
        );
    }

    #[test]
    fn build_apdu_ext_extended_form_over_255() {
        let data = vec![0xAAu8; 300];
        let apdu = build_apdu_ext(0x00, 0x87, 0x07, 0x9A, &data, Some(0));
        assert_eq!(&apdu[..5], &[0x00, 0x87, 0x07, 0x9A, 0x00]);
        assert_eq!(&apdu[5..7], &[0x01, 0x2C]); // 300 = 0x012C
        assert_eq!(&apdu[7..7 + 300], data.as_slice());
        assert_eq!(&apdu[7 + 300..], &[0x00, 0x00]); // Le=0 -> 65536, two bytes
    }

    #[test]
    fn chain_apdu_single_chunk_clears_chain_bit_and_keeps_le() {
        let chunks = chain_apdu(0x00, 0x87, 0x11, 0x9A, &[0xAA, 0xBB], 254, Some(0x00));
        assert_eq!(chunks.len(), 1);
        assert_eq!(
            chunks[0],
            vec![0x00, 0x87, 0x11, 0x9A, 0x02, 0xAA, 0xBB, 0x00]
        );
    }

    #[test]
    fn chain_apdu_multi_chunk_reassembles_and_only_final_has_le() {
        let data = vec![0x5Au8; 300];
        let chunks = chain_apdu(0x00, 0x87, 0x07, 0x9A, &data, 254, Some(0x00));
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0][0], 0x10); // chaining bit set on first link
        assert_eq!(&chunks[0][1..4], &[0x87, 0x07, 0x9A]);
        assert_eq!(chunks[0][4], 254);
        assert_eq!(chunks[0].len(), 5 + 254); // no Le on intermediate link
        assert_eq!(chunks[1][0], 0x00); // chaining bit cleared on last link
        let last_lc = chunks[1][4] as usize;
        assert_eq!(last_lc, 300 - 254);
        assert_eq!(&chunks[1][5 + last_lc..], &[0x00]); // Le on final link only

        let mut reassembled = Vec::new();
        reassembled.extend_from_slice(&chunks[0][5..5 + 254]);
        reassembled.extend_from_slice(&chunks[1][5..5 + last_lc]);
        assert_eq!(reassembled, data);
    }
}
