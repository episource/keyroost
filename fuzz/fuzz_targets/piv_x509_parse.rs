//! PIV X.509/DER certificate parsers — the SPKI-fallback path (#97) hands
//! these raw certificate bytes read off the card, so a hostile or corrupt
//! card body must produce an error, never a panic or unbounded allocation.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keyroost_piv::x509_parse::parse_subject_dn(data);
    let _ = keyroost_piv::x509_parse::parse_key_policy_extension(data);
    let _ = keyroost_piv::x509_parse::parse_spki_key_alg(data);
});
