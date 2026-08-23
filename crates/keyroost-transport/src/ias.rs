//! IAS Classic/ECC (Thales eToken 5300 and similar) over PC/SC.
//!
//! Drives an IAS Classic/ECC smart-card applet using the pure-byte
//! builders/parsers in [`keyroost_ias`]. Same shape as [`crate::PivSession`]:
//! card transmit, the `61xx`/GET RESPONSE reassembly loop (shared with every
//! other applet session in this crate via [`crate::transmit_applet`]),
//! reader discovery, a status view, and the write surface this workspace
//! ported from PIV where an IAS equivalent exists: admin-key authentication,
//! PIN/PUK change and unblock, key generation, certificate import/export,
//! and signing.
//!
//! **No hardware was available to trace this against** — see
//! `keyroost-ias`'s crate doc comment and `CLAUDE.md`'s "Known soft spots"
//! for what's confirmed vs. guessed. The two highest-uncertainty pieces are
//! kept in single, isolated functions so a correction is a point-edit: AID
//! selection ([`IasSession::open`]'s candidate loop, plus the `aid_override`
//! it accepts) and the admin-key crypto ([`admin_crypt`]).

use crate::TransportError;
use keyroost_ias as ias;
use keyroost_ias::{FidTable, IasAdminAlg, KeyAlg, PublicKey, Slot};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// A read-only snapshot of an IAS applet's state.
#[derive(Debug, Clone)]
pub struct IasStatus {
    /// The AID that actually answered SELECT for this session.
    pub aid: Vec<u8>,
    /// Remaining PIN tries from a no-op VERIFY (`63 Cx`); `Some(0)` when
    /// blocked, `None` when the card didn't report a count.
    pub pin_retries: Option<u8>,
    /// Per-slot certificate presence, in canonical slot order.
    pub slots: Vec<IasSlotStatus>,
}

/// Whether a given IAS key slot holds a certificate (and its size).
#[derive(Debug, Clone)]
pub struct IasSlotStatus {
    pub slot: Slot,
    pub cert_present: bool,
    pub cert_len: usize,
}

/// An open IAS applet session on one PC/SC reader.
pub struct IasSession {
    card: Card,
    debug: bool,
    /// The AID that answered SELECT — recorded for [`IasStatus`], and so a
    /// caller can report back exactly what worked once bring-up finds it.
    aid: Vec<u8>,
    fids: FidTable,
    /// Session-local public-key cache, same role as `PivSession`'s: IAS has
    /// no metadata query to re-report a freshly generated key, so a caller
    /// needing it in a *later* session must re-supply it (see
    /// [`Self::remember_pubkey`]).
    pubkey_cache: HashMap<u8, (KeyAlg, PublicKey)>,
}

impl IasSession {
    /// Connect to `reader_name` and SELECT an IAS applet. Tries
    /// `aid_override` first (when given), then every
    /// [`keyroost_ias::CANDIDATE_AIDS`] in order. Returns
    /// [`TransportError::NoIasApplet`] when nothing answers.
    pub fn open(
        reader_name: &str,
        aid_override: Option<&[u8]>,
        fids: FidTable,
    ) -> Result<Self, TransportError> {
        let ctx = Context::establish(Scope::User).map_err(TransportError::PcscUnavailable)?;
        let cstr = std::ffi::CString::new(reader_name)
            .map_err(|_| TransportError::MalformedResponse("reader name contained NUL"))?;
        let card = ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
        let mut session = Self {
            card,
            debug: false,
            aid: Vec::new(),
            fids,
            pubkey_cache: HashMap::new(),
        };
        session.select(aid_override)?;
        Ok(session)
    }

    /// Enable per-APDU stderr tracing.
    pub fn set_debug(&mut self, on: bool) {
        self.debug = on;
    }

    /// Names of connected readers whose card answers SELECT for any
    /// candidate AID.
    pub fn list_ias_readers() -> Result<Vec<String>, TransportError> {
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
                let mut session = IasSession {
                    card,
                    debug: false,
                    aid: Vec::new(),
                    fids: FidTable::default(),
                    pubkey_cache: HashMap::new(),
                };
                if session.select(None).is_ok() {
                    out.push(name.to_string_lossy().into_owned());
                }
                // Release without resetting — probing must not disturb cards
                // other sessions hold open (same reasoning as PivSession's).
                let _ = session.card.disconnect(pcsc::Disposition::LeaveCard);
            }
        }
        Ok(out)
    }

    fn select(&mut self, aid_override: Option<&[u8]>) -> Result<(), TransportError> {
        let mut candidates: Vec<&[u8]> = Vec::new();
        if let Some(a) = aid_override {
            candidates.push(a);
        }
        candidates.extend(ias::CANDIDATE_AIDS);
        for aid in candidates {
            let (_, sw) = self.transmit_full(&ias::select(aid))?;
            if sw == ias::SW_OK {
                self.aid = aid.to_vec();
                return Ok(());
            }
        }
        Err(TransportError::NoIasApplet)
    }

    /// Read a read-only status snapshot: PIN retries and which slots hold a
    /// certificate. No PIN, no admin-key auth.
    pub fn status(&mut self) -> Result<IasStatus, TransportError> {
        let pin_retries = self.pin_retries();
        let mut slots = Vec::with_capacity(3);
        for slot in Slot::all() {
            let cert = self.read_certificate(slot)?;
            slots.push(IasSlotStatus {
                slot,
                cert_present: cert.is_some(),
                cert_len: cert.map(|d| d.len()).unwrap_or(0),
            });
        }
        Ok(IasStatus {
            aid: self.aid.clone(),
            pin_retries,
            slots,
        })
    }

    /// Remaining PIN tries via a no-op VERIFY. `63 Cx` -> `Some(x)`, `6983`
    /// (blocked) -> `Some(0)`, `9000`/anything else -> `None`.
    fn pin_retries(&mut self) -> Option<u8> {
        let (_, sw) = self.transmit_full(&ias::verify_pin_status()).ok()?;
        if let Some(n) = crate::sw_tries_remaining(sw) {
            Some(n)
        } else if sw == ias::SW_AUTH_BLOCKED {
            Some(0)
        } else {
            None
        }
    }

    /// Authenticate to the admin/SO key via GET CHALLENGE + EXTERNAL
    /// AUTHENTICATE. Required before key generation, certificate import,
    /// admin-key change, and set-pin-retries. **The crypto underneath
    /// (`admin_crypt`) is the single highest-uncertainty piece of this whole
    /// feature — unconfirmed against real hardware.** See this module's
    /// doc comment and `CLAUDE.md`'s "Known soft spots".
    pub fn authenticate_admin(
        &mut self,
        alg: IasAdminAlg,
        key: &[u8],
    ) -> Result<(), TransportError> {
        if key.len() != alg.key_len() {
            return Err(TransportError::IasBadKeyLength);
        }
        let (challenge, sw) = self.transmit_full(&ias::get_challenge(alg.block_size() as u8))?;
        ok_or_apdu("ias get challenge", sw)?;
        let response = Zeroizing::new(admin_crypt(alg, key, &challenge)?);
        let (_, sw2) =
            self.transmit_full(&ias::external_authenticate(ias::ADMIN_KEY_REF, &response))?;
        if sw2 != ias::SW_OK {
            return Err(TransportError::IasAdminAuthFailed);
        }
        // Unlike PIV's mutual auth, EXTERNAL AUTHENTICATE is one-directional
        // by design (ISO 7816-4): the card does not prove itself back to the
        // host. `9000` here is the whole answer.
        Ok(())
    }

    /// Present the PIN. Required before private-key use.
    pub fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        let apdu =
            Zeroizing::new(ias::verify_pin(pin).map_err(|_| TransportError::IasBadPinLength)?);
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Change the PIN. A wrong `old` PIN consumes a try and reports the count.
    pub fn change_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            ias::change_reference_data(old, new).map_err(|_| TransportError::IasBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Unblock the PIN using the PUK (unblock code), setting a new PIN. A
    /// wrong PUK consumes a try and reports the count. `[GUESS]` whether
    /// this is a distinct secret from the admin key on the real card — see
    /// `CLAUDE.md`'s "Known soft spots".
    pub fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(
            ias::reset_retry_counter(puk, new_pin).map_err(|_| TransportError::IasBadPinLength)?,
        );
        let (_, sw) = self.transmit_full(&apdu)?;
        map_pin_sw(sw)
    }

    /// Replace the admin/SO key. Requires prior admin-key auth under the
    /// *old* key.
    pub fn change_admin_key(&mut self, old: &[u8], new: &[u8]) -> Result<(), TransportError> {
        let apdu = Zeroizing::new(ias::change_admin_key(old, new));
        let (_, sw) = self.transmit_full(&apdu)?;
        ok_or_write("ias change admin key", sw)
    }

    /// "Change the PUK" — reuses [`Self::change_pin`]'s reference (there is
    /// no separate PUK-change instruction in this byte layer; RESET RETRY
    /// COUNTER already *is* the PUK-consuming operation). Kept as its own
    /// method only so callers mirroring PIV's four-method shape have a
    /// direct analog; if a real card turns out to have a genuinely separate
    /// PUK-change command, only this method needs to change.
    pub fn change_puk(&mut self, old_puk: &[u8], new_puk: &[u8]) -> Result<(), TransportError> {
        self.change_pin(old_puk, new_puk)
    }

    /// Set the PIN retry count. **`[UNKNOWN]`, deliberately unimplemented in
    /// v1**: no ISO 7816-4/-8 base instruction covers this (PIV's SET PIN
    /// RETRIES is a Yubico extension with no IAS analog), and unlike this
    /// crate's other `[GUESS]` builders — which at least follow a reasoned
    /// ISO 7816-8 convention (a CRT tag, a PSO P1/P2 pairing) — there is no
    /// defensible placeholder byte sequence to send here at all. Fabricating
    /// one and sending it to real hardware risks the card interpreting it as
    /// some *other*, unintended command, which is a worse failure mode than
    /// simply refusing. Always returns [`TransportError::IasNotSupported`];
    /// revisit once a real device trace shows whether this card's profile
    /// exposes anything for it.
    pub fn set_pin_retries(&mut self, _tries: u8) -> Result<(), TransportError> {
        Err(TransportError::IasNotSupported("set pin retries"))
    }

    /// Generate a fresh asymmetric key pair in `slot`, returning its public
    /// key. Requires prior admin-key auth. Overwrites any existing key in
    /// the slot.
    ///
    /// On success, also caches `(alg, public key)` for `slot` in this
    /// session's in-memory key cache — IAS has no metadata query to re-report
    /// a freshly generated key later, so [`Self::slot_key`] falls back to
    /// this. See [`Self::remember_pubkey`] for carrying it to a later session.
    pub fn generate_key(&mut self, slot: Slot, alg: KeyAlg) -> Result<PublicKey, TransportError> {
        let (data, sw) = self.transmit_full(&ias::generate_key_pair(slot, alg))?;
        ok_or_write("ias generate key", sw)?;
        let key = ias::parse_generated_public_key(&data).map_err(TransportError::IasParse)?;
        self.pubkey_cache
            .insert(slot.key_ref(), (alg, key.clone()));
        Ok(key)
    }

    /// Seed this session's in-memory key cache for `slot` with `(alg, key)`
    /// directly, without a card round-trip — the cross-session bridge for
    /// CSR/self-sign after a key generated in an earlier `keyroostctl`
    /// invocation (or the GUI's fresh-session-per-action pattern). Not
    /// verified against the card in any way.
    pub fn remember_pubkey(&mut self, slot: Slot, alg: KeyAlg, key: PublicKey) {
        self.pubkey_cache.insert(slot.key_ref(), (alg, key));
    }

    /// Import a DER-encoded X.509 certificate into `slot`'s certificate file.
    /// Requires prior admin-key auth. Tries a single extended-length UPDATE
    /// BINARY first; a certificate big enough to need one (any real X.509
    /// cert typically is) that gets rejected falls back to ISO 7816-4
    /// command chaining, same fallback shape as [`Self::sign`].
    pub fn import_certificate(&mut self, slot: Slot, der: &[u8]) -> Result<(), TransportError> {
        let fid = self.fids.fid_for(slot);
        let (_, sw) = self.transmit_full(&ias::select_file_fid(fid))?;
        ok_or_apdu("ias select certificate file", sw)?;
        let apdu = ias::update_binary(0, der);
        let sw = if force_chaining() {
            self.transmit_chain(
                "ias import certificate",
                &ias::update_binary_chained(0, der, CHAIN_CHUNK),
            )?
            .1
        } else {
            let (_, sw) = self.transmit_full(&apdu)?;
            if sw == ias::SW_OK || !uses_extended_length(&apdu) {
                sw
            } else {
                self.transmit_chain(
                    "ias import certificate",
                    &ias::update_binary_chained(0, der, CHAIN_CHUNK),
                )?
                .1
            }
        };
        ok_or_write("ias import certificate", sw)
    }

    /// Best-effort clear of `slot`'s certificate file (write a zero-length
    /// body). `[GUESS]` — low confidence this is a meaningful "delete" on a
    /// plain-binary-file card model; the key itself is untouched either way.
    pub fn clear_certificate(&mut self, slot: Slot) -> Result<(), TransportError> {
        let fid = self.fids.fid_for(slot);
        let (_, sw) = self.transmit_full(&ias::select_file_fid(fid))?;
        ok_or_apdu("ias select certificate file", sw)?;
        let (_, sw) = self.transmit_full(&ias::update_binary(0, &[]))?;
        ok_or_write("ias clear certificate", sw)
    }

    /// Read the DER-encoded certificate stored in `slot`'s certificate file,
    /// or `None` when the file doesn't exist or is empty. No PIN required.
    pub fn read_certificate(&mut self, slot: Slot) -> Result<Option<Vec<u8>>, TransportError> {
        let fid = self.fids.fid_for(slot);
        let (_, sw) = self.transmit_full(&ias::select_file_fid(fid))?;
        if sw != ias::SW_OK {
            return Ok(None);
        }
        let (data, sw) = self.transmit_full(&ias::read_binary(0, 0))?;
        if sw != ias::SW_OK || data.is_empty() {
            return Ok(None);
        }
        Ok(Some(data))
    }

    /// Whether `slot` holds a private key. `[GUESS]` — no metadata query
    /// exists to ask directly, so this infers occupancy from whether a
    /// signature attempt is even meaningful: this session's own pubkey
    /// cache, or (failing that) whether the slot's certificate exists, which
    /// on most provisioning flows implies a key was generated for it.
    pub fn slot_has_key(&mut self, slot: Slot) -> Result<bool, TransportError> {
        if self.pubkey_cache.contains_key(&slot.key_ref()) {
            return Ok(true);
        }
        Ok(self.read_certificate(slot)?.is_some())
    }

    /// The algorithm and public key of the key stored in `slot`: from this
    /// session's in-memory key cache (populated by [`Self::generate_key`] or
    /// [`Self::remember_pubkey`]), else parsed from the slot's certificate's
    /// SubjectPublicKeyInfo. Errors when neither source has anything.
    pub fn slot_key(&mut self, slot: Slot) -> Result<(KeyAlg, PublicKey), TransportError> {
        if let Some(cached) = self.pubkey_cache.get(&slot.key_ref()).cloned() {
            return Ok(cached);
        }
        let der = self.read_certificate(slot)?.ok_or(
            TransportError::MalformedResponse(
                "slot has no key: no certificate to read one from, and nothing was \
                 generated into this slot in this session — run `ias generate-key` \
                 on this slot in this same session, or pass its previously saved \
                 key material to this command",
            ),
        )?;
        let (piv_alg, key) = keyroost_piv::x509_parse::parse_subject_public_key_info(&der)
            .map_err(|_| {
                TransportError::MalformedResponse("slot certificate's public key is unparseable")
            })?;
        let alg = KeyAlg::from_piv_alg(piv_alg).ok_or(TransportError::MalformedResponse(
            "slot certificate's key algorithm has no IAS analog",
        ))?;
        Ok((alg, key))
    }

    /// Ask `slot`'s private key to sign a *prepared* block via PSO:COMPUTE
    /// DIGITAL SIGNATURE: a full PKCS#1 v1.5 padded block for RSA, the raw
    /// hash for ECDSA. Requires a verified PIN. Tries a single
    /// extended-length APDU first, falling back to command chaining when
    /// that gets rejected after actually using extended-length encoding —
    /// same fallback shape as [`Self::import_certificate`].
    ///
    /// `alg` isn't needed by [`ias::pso_compute_signature`]'s framing itself
    /// (PSO:CDS carries no algorithm/key-reference bytes — it signs whatever
    /// the currently-selected security environment points at); it's taken
    /// here only so a future MSE:SET pre-step (see
    /// [`ias::manage_security_environment`]) has it to hand if a trace shows
    /// one is needed, without changing this method's signature.
    pub fn sign(&mut self, _alg: KeyAlg, prepared: &[u8]) -> Result<Vec<u8>, TransportError> {
        let apdu = ias::pso_compute_signature(prepared);
        let (data, sw) = if force_chaining() {
            self.transmit_chain(
                "ias sign",
                &ias::pso_compute_signature_chained(prepared, CHAIN_CHUNK),
            )?
        } else {
            let (data, sw) = self.transmit_full(&apdu)?;
            if sw == ias::SW_OK || !uses_extended_length(&apdu) {
                (data, sw)
            } else {
                self.transmit_chain(
                    "ias sign",
                    &ias::pso_compute_signature_chained(prepared, CHAIN_CHUNK),
                )?
            }
        };
        ok_or_write("ias sign", sw)?;
        Ok(data)
    }

    /// Build a PKCS#10 certificate-signing request for the key in `slot`,
    /// signed on the card, returned as PEM. The slot must hold a key and the
    /// PIN must already be verified. Reuses `keyroost_piv::x509`'s DER
    /// builders directly (pure DER, algorithm-shape-driven, not
    /// PIV-protocol-driven — see `keyroost-ias`'s crate doc comment).
    pub fn generate_csr(&mut self, slot: Slot, subject: &str) -> Result<String, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let piv_alg = alg.to_piv_alg();
        let subject =
            keyroost_piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = keyroost_piv::spki::subject_public_key_info(&key, piv_alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        let cri = keyroost_piv::x509::csr_info(&subject, &spki);
        let prepared = prepared_block(piv_alg, &cri)?;
        let sig = self.sign(alg, &prepared)?;
        let der = keyroost_piv::x509::assemble(&cri, piv_alg, &sig).map_err(TransportError::X509)?;
        Ok(keyroost_piv::x509::pem_csr(&der))
    }

    /// Create a self-signed certificate for the key in `slot` (validity in
    /// unix seconds), sign it on the card, import it into the slot, and
    /// return the DER. Requires a verified PIN (signature) and prior
    /// admin-key auth (import).
    pub fn self_signed_certificate(
        &mut self,
        slot: Slot,
        subject: &str,
        not_before: i64,
        not_after: i64,
    ) -> Result<Vec<u8>, TransportError> {
        let (alg, key) = self.slot_key(slot)?;
        let piv_alg = alg.to_piv_alg();
        let subject =
            keyroost_piv::x509::SubjectName::parse(subject).map_err(TransportError::X509)?;
        let spki = keyroost_piv::spki::subject_public_key_info(&key, piv_alg)
            .map_err(|_| TransportError::MalformedResponse("slot key/algorithm mismatch"))?;
        let mut serial = [0u8; 16];
        getrandom::getrandom(&mut serial).map_err(|_| TransportError::HostRngFailed)?;
        let tbs = keyroost_piv::x509::tbs_certificate(
            &serial, piv_alg, &subject, not_before, not_after, &spki,
        )
        .map_err(TransportError::X509)?;
        let prepared = prepared_block(piv_alg, &tbs)?;
        let sig = self.sign(alg, &prepared)?;
        let der = keyroost_piv::x509::assemble(&tbs, piv_alg, &sig).map_err(TransportError::X509)?;
        self.import_certificate(slot, &der)?;
        Ok(der)
    }

    /// Transmit one APDU and reassemble a response the card splits across
    /// `61xx` continuations, returning `(payload, sw)`. Reuses the exact
    /// crate-shared reassembly core [`PivSession`](crate::PivSession) does.
    fn transmit_full(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), TransportError> {
        // Redact bodies that carry secret material: VERIFY (20), CHANGE
        // REFERENCE DATA (24), RESET RETRY COUNTER (2C), EXTERNAL
        // AUTHENTICATE (82), PERFORM SECURITY OPERATION (2A, the signing
        // payload).
        let cmd_sensitive = matches!(
            apdu.get(1),
            Some(0x20) | Some(0x24) | Some(0x2C) | Some(0x82) | Some(0x2A)
        );
        let resp_sensitive = apdu.get(1) == Some(&0x2A);
        const IO: crate::AppletIo = crate::AppletIo {
            label: "ias",
            more_data_sw: ias::SW_MORE_DATA,
            get_response: ias::get_response,
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

    /// Transmit an ISO 7816-4 command-chaining sequence: every intermediate
    /// chunk must be accepted with `9000` or the chain aborts; the final
    /// chunk's status word and reassembled response are returned as-is.
    /// Mirrors the same fallback this workspace uses elsewhere for
    /// extended-length rejection.
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
            if sw != ias::SW_OK {
                return Err(TransportError::Apdu {
                    label,
                    sw1: (sw >> 8) as u8,
                    sw2: sw as u8,
                });
            }
        }
        Ok((Vec::new(), ias::SW_OK)) // unreachable: chunk builders never return an empty list
    }
}

/// Chunk size for the command-chaining fallback, matching the 254-byte
/// chunks this workspace's other applet sessions use.
const CHAIN_CHUNK: usize = 254;

/// Whether `apdu` used extended-length encoding: byte 4 is the `0x00`
/// extended-length marker. The builders this is checked against
/// (`update_binary`, `pso_compute_signature`) never emit a zero short-form
/// `Lc` for a non-empty body, so this is unambiguous.
fn uses_extended_length(apdu: &[u8]) -> bool {
    apdu.get(4) == Some(&0x00)
}

/// `KEYROOST_IAS_FORCE_CHAINING` forces the command-chaining path — mirrors
/// `KEYROOST_PIV_FORCE_CHAINING`/`KEYROOST_OPENPGP_FORCE_CHAINING`.
fn force_chaining() -> bool {
    std::env::var_os("KEYROOST_IAS_FORCE_CHAINING").is_some()
}

/// Turn to-be-signed bytes into the block PSO:COMPUTE DIGITAL SIGNATURE
/// expects: PKCS#1 v1.5 over SHA-256 for RSA (the card does raw RSA), the
/// bare SHA-256/384 digest for ECDSA. Reuses `keyroost_piv::x509`'s hash
/// selection and padding — pure DER/hash math, not PIV-protocol-specific.
fn prepared_block(alg: keyroost_piv::KeyAlg, tbs: &[u8]) -> Result<Vec<u8>, TransportError> {
    use keyroost_piv::x509::{self, SigHash};
    match x509::signature_hash(alg).map_err(TransportError::X509)? {
        SigHash::Sha256 => {
            let digest = keyroost_proto::sha256::sha256(tbs);
            let rsa_k = match alg {
                keyroost_piv::KeyAlg::Rsa2048 => Some(256),
                keyroost_piv::KeyAlg::Rsa3072 => Some(384),
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

/// Map an IAS status word to success or a labelled APDU error.
fn ok_or_apdu(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == ias::SW_OK {
        Ok(())
    } else {
        Err(TransportError::Apdu {
            label,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// Like [`ok_or_apdu`] but maps the "security status not satisfied" word a
/// write returns when admin-key auth or the PIN hasn't been presented.
fn ok_or_write(label: &'static str, sw: u16) -> Result<(), TransportError> {
    if sw == ias::SW_SECURITY_NOT_SATISFIED {
        Err(TransportError::IasSecurityNotSatisfied)
    } else {
        ok_or_apdu(label, sw)
    }
}

/// Map a PIN/PUK-verification status word: `9000` ok, `63 Cx`/`6983`
/// rejected with the remaining-try count, anything else a generic APDU error.
fn map_pin_sw(sw: u16) -> Result<(), TransportError> {
    if sw == ias::SW_OK {
        Ok(())
    } else if let Some(n) = crate::sw_tries_remaining(sw) {
        Err(TransportError::IasPinRejected {
            tries_remaining: Some(n),
        })
    } else if sw == ias::SW_AUTH_BLOCKED {
        Err(TransportError::IasPinRejected {
            tries_remaining: Some(0),
        })
    } else {
        Err(TransportError::Apdu {
            label: "ias pin/puk",
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        })
    }
}

/// Encrypt the GET CHALLENGE nonce under the admin key for EXTERNAL
/// AUTHENTICATE. **`[UNKNOWN]`**: cipher choice (3DES/AES) is the one thing
/// [`IasAdminAlg`] pins down; mode, IV, and whether a MAC is required are
/// all unconfirmed. A single-block CBC-with-zero-IV encryption is
/// mathematically identical to plain ECB for one block (the IV XORs into
/// the first — and only — block before encryption), so this doubles as a
/// defensible guess at either convention for a challenge that's always
/// exactly one block long ([`IasAdminAlg::block_size`]). Kept as one
/// isolated function precisely so a real card's actual requirement (a
/// different mode, an appended MAC, …) is a rewrite here only.
fn admin_crypt(alg: IasAdminAlg, key: &[u8], challenge: &[u8]) -> Result<Vec<u8>, TransportError> {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockEncrypt, KeyInit};

    if challenge.len() != alg.block_size() {
        return Err(TransportError::MalformedResponse(
            "IAS challenge length did not match the admin algorithm's block size",
        ));
    }

    fn enc<C: BlockEncrypt>(c: &C, data: &[u8]) -> Vec<u8> {
        let mut block = GenericArray::clone_from_slice(data);
        c.encrypt_block(&mut block);
        block.to_vec()
    }

    let bad = |_| TransportError::IasBadKeyLength;
    match alg {
        IasAdminAlg::TripleDes => {
            let c = des::TdesEde3::new_from_slice(key).map_err(bad)?;
            Ok(enc(&c, challenge))
        }
        IasAdminAlg::Aes128 => {
            let c = aes::Aes128::new_from_slice(key).map_err(bad)?;
            Ok(enc(&c, challenge))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_extended_length_detects_the_00_marker() {
        let short = ias::pso_compute_signature(&[0x01, 0x02]);
        assert!(!uses_extended_length(&short));
        let ext = ias::pso_compute_signature(&[0u8; 300]);
        assert!(uses_extended_length(&ext));
    }

    #[test]
    fn admin_crypt_rejects_wrong_challenge_length() {
        let err = admin_crypt(IasAdminAlg::TripleDes, &[0u8; 24], &[0u8; 4]).unwrap_err();
        assert!(matches!(err, TransportError::MalformedResponse(_)));
    }

    #[test]
    fn admin_crypt_3des_produces_one_block() {
        let out = admin_crypt(IasAdminAlg::TripleDes, &[0x11u8; 24], &[0x22u8; 8]).unwrap();
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn admin_crypt_aes128_produces_one_block() {
        let out = admin_crypt(IasAdminAlg::Aes128, &[0x11u8; 16], &[0x22u8; 16]).unwrap();
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn map_pin_sw_variants() {
        assert!(map_pin_sw(ias::SW_OK).is_ok());
        assert_eq!(
            map_pin_sw(0x63C3).unwrap_err().to_string(),
            TransportError::IasPinRejected {
                tries_remaining: Some(3)
            }
            .to_string()
        );
        assert_eq!(
            map_pin_sw(ias::SW_AUTH_BLOCKED).unwrap_err().to_string(),
            TransportError::IasPinRejected {
                tries_remaining: Some(0)
            }
            .to_string()
        );
    }
}
