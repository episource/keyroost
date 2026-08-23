//! IAS response parsers — device-supplied BER.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_ias::read_ber_len(data);
    let _ = keyroost_ias::find_tlv(data, 0x80);
    let _ = keyroost_ias::find_tlv(data, 0x84);
    let _ = keyroost_ias::parse_generated_public_key(data);
});
