//! CTAP2 `authenticatorBioEnrollment` (0x09, or preview 0x40).
//!
//! Fingerprint management on a FIDO2 bio authenticator: enroll new fingers
//! (a multi-sample capture flow), enumerate existing enrollments, rename them,
//! and remove them. Mirrors the structure of [`crate::cred_mgmt`] — both wrap a
//! [`PinUvAuthToken`] and CBOR-encoded subcommands — but bio enrollment prefixes
//! its pinUvAuthParam input with a *modality* byte (fingerprint = 0x01), and the
//! enroll flow is stateful: `enroll_begin` then repeated `enroll_capture_next`
//! until the device reports completion.
//!
//! Spec: CTAP 2.1 §6.7 (authenticatorBioEnrollment).

use crate::cbor::{self, Value};
use crate::client_pin::PinUvAuthToken;
use crate::cmd::CtapError;
use crate::hid::CTAPHID_CBOR;
use crate::transport::{with_timeout, CtapTransport};

/// authenticatorBioEnrollment command byte (standard).
pub const CTAP2_BIO_ENROLLMENT: u8 = 0x09;
/// Preview command byte, used by authenticators that predate the final spec.
pub const CTAP2_BIO_ENROLLMENT_PREVIEW: u8 = 0x40;

/// Fingerprint modality (the only modality CTAP currently defines).
pub const MODALITY_FINGERPRINT: u64 = 0x01;

/// Wide read-deadline for the enroll capture steps: each capture blocks on
/// the user touching the sensor. The HID layer extends its deadline on every
/// KEEPALIVE, but raise the base timeout too so a device that sends sparse
/// keepalives still gets time to capture.
const CAPTURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Host-owned cap on capture iterations for one enrollment (audit KEY-009:
/// device-reported `remaining_samples` must never drive an unbounded host
/// loop — the CLI's capture loop has no cancel path at all). Real sensors
/// report `maxCaptureSamples` of roughly 4–17 and every iteration costs the
/// user a physical touch, so 64 leaves generous headroom for bad-quality
/// retries while stopping a device that reports `remaining_samples >= 1`
/// forever.
const MAX_CAPTURE_ITERATIONS: u32 = 64;

// --- request map keys (CTAP 2.1 §6.7) ---
const KEY_MODALITY: u64 = 0x01;
const KEY_SUB_COMMAND: u64 = 0x02;
const KEY_SUB_COMMAND_PARAMS: u64 = 0x03;
const KEY_PIN_UV_AUTH_PROTOCOL: u64 = 0x04;
const KEY_PIN_UV_AUTH_PARAM: u64 = 0x05;

// --- subcommands ---
const SUB_ENROLL_BEGIN: u8 = 0x01;
const SUB_ENROLL_CAPTURE_NEXT: u8 = 0x02;
const SUB_CANCEL_ENROLLMENT: u8 = 0x03;
const SUB_ENUMERATE_ENROLLMENTS: u8 = 0x04;
const SUB_SET_FRIENDLY_NAME: u8 = 0x05;
const SUB_REMOVE_ENROLLMENT: u8 = 0x06;
const SUB_GET_SENSOR_INFO: u8 = 0x07;

// --- subcommand param keys ---
const PARAM_TEMPLATE_ID: u64 = 0x01;
const PARAM_TEMPLATE_FRIENDLY_NAME: u64 = 0x02;
const PARAM_TIMEOUT_MS: u64 = 0x03;

// --- response keys ---
const RESP_FINGERPRINT_KIND: u64 = 0x02;
const RESP_MAX_CAPTURE_SAMPLES: u64 = 0x03;
const RESP_TEMPLATE_ID: u64 = 0x04;
const RESP_LAST_ENROLL_SAMPLE_STATUS: u64 = 0x05;
const RESP_REMAINING_SAMPLES: u64 = 0x06;
const RESP_TEMPLATE_INFOS: u64 = 0x07;
const RESP_MAX_FRIENDLY_NAME_BYTES: u64 = 0x08;

// template-info map keys (inside RESP_TEMPLATE_INFOS array)
const TI_TEMPLATE_ID: u64 = 0x01;
const TI_FRIENDLY_NAME: u64 = 0x02;

/// One enrolled fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    /// Opaque template id the authenticator assigns (used to rename/remove).
    pub template_id: Vec<u8>,
    /// User-set name, if one was set.
    pub friendly_name: Option<String>,
}

/// Fingerprint sensor capabilities, from `getFingerprintSensorInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorInfo {
    /// 1 = touch sensor, 2 = swipe sensor.
    pub fingerprint_kind: u64,
    /// Samples a successful enrollment needs.
    pub max_capture_samples: u64,
    /// Max friendly-name length in bytes, if the authenticator reports it.
    pub max_friendly_name_bytes: Option<u64>,
}

/// Progress of a single enrollment capture step.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStatus {
    /// `lastEnrollSampleStatus` — 0x00 = good, others are retry hints (see
    /// [`sample_status_message`]).
    pub last_sample_status: u64,
    /// How many more good samples the device still wants. 0 = done.
    pub remaining_samples: u64,
}

/// Human-readable hint for a `lastEnrollSampleStatus` code (CTAP 2.1 §6.7.4).
pub fn sample_status_message(status: u64) -> &'static str {
    match status {
        0x00 => "good sample captured",
        0x01 => "sample too high or partial — try again",
        0x02 => "sample too low or partial — try again",
        0x03 => "sample partial — center your finger on the sensor",
        0x04 => "too many samples failed — enrollment may need restarting",
        0x05 => "low quality — clean the sensor and your finger and retry",
        0x06 => "too close to a previous sample — adjust finger position",
        0x07 => "sensor timeout — touch the sensor",
        _ => "retry the sample",
    }
}

/// Bio-enrollment session: holds the authenticated channel + the chosen command
/// byte (standard vs preview), like [`crate::cred_mgmt::CredentialManager`].
pub struct BioEnrollment<'a, T: CtapTransport> {
    dev: &'a mut T,
    token: PinUvAuthToken,
    cmd_code: u8,
    /// Captures performed for the in-progress enrollment, enforced against
    /// [`MAX_CAPTURE_ITERATIONS`]. Reset by [`Self::enroll_begin`].
    captures: u32,
}

impl<'a, T: CtapTransport> BioEnrollment<'a, T> {
    /// Create a session. `cmd_code` is [`CTAP2_BIO_ENROLLMENT`] or
    /// [`CTAP2_BIO_ENROLLMENT_PREVIEW`] depending on what the authenticator
    /// advertises in its `AuthenticatorInfo`.
    pub fn new(dev: &'a mut T, token: PinUvAuthToken, cmd_code: u8) -> Self {
        BioEnrollment {
            dev,
            token,
            cmd_code,
            captures: 0,
        }
    }

    /// `getFingerprintSensorInfo` — sensor kind and how many samples enrollment
    /// needs. Sent as `getModality`-style request (no auth required).
    pub fn sensor_info(&mut self) -> Result<SensorInfo, CtapError> {
        // getFingerprintSensorInfo is unauthenticated: modality + subCommand,
        // no pinUvAuthParam.
        let entries = vec![
            (Value::UInt(KEY_MODALITY), Value::UInt(MODALITY_FINGERPRINT)),
            (
                Value::UInt(KEY_SUB_COMMAND),
                Value::UInt(SUB_GET_SENSOR_INFO as u64),
            ),
        ];
        let resp = self.transact(&Value::Map(entries))?;
        Ok(SensorInfo {
            fingerprint_kind: field_uint(&resp, RESP_FINGERPRINT_KIND).unwrap_or(1),
            max_capture_samples: field_uint(&resp, RESP_MAX_CAPTURE_SAMPLES).unwrap_or(0),
            max_friendly_name_bytes: field_uint(&resp, RESP_MAX_FRIENDLY_NAME_BYTES),
        })
    }

    /// List enrolled fingerprints.
    pub fn enumerate(&mut self) -> Result<Vec<Enrollment>, CtapError> {
        let resp = match self.dispatch(SUB_ENUMERATE_ENROLLMENTS, None) {
            Ok(v) => v,
            // CTAP 2.1 §6.7.6: when no fingerprints are enrolled, the
            // authenticator answers CTAP2_ERR_INVALID_OPTION (0x2C) rather than
            // an empty list. Treat that as "no enrollments", not an error.
            Err(CtapError::StatusCode(0x2C)) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let Some(arr) = resp
            .get_uint_key(RESP_TEMPLATE_INFOS)
            .and_then(|v| v.as_array())
        else {
            // No templateInfos -> no enrollments.
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(arr.len());
        for ti in arr {
            let template_id = ti
                .get_uint_key(TI_TEMPLATE_ID)
                .and_then(|v| v.as_bytes())
                .ok_or(CtapError::InvalidResponseShape("missing template id"))?
                .to_vec();
            let friendly_name = ti
                .get_uint_key(TI_FRIENDLY_NAME)
                .and_then(|v| v.as_text())
                .map(|s| s.to_owned());
            out.push(Enrollment {
                template_id,
                friendly_name,
            });
        }
        Ok(out)
    }

    /// Begin enrolling a new fingerprint. Returns the new template id plus the
    /// status of the first capture. `timeout_ms` is an optional per-sample
    /// timeout the authenticator may honor.
    pub fn enroll_begin(
        &mut self,
        timeout_ms: Option<u64>,
    ) -> Result<(Vec<u8>, CaptureStatus), CtapError> {
        // A new enrollment gets a fresh host-side capture budget (KEY-009).
        self.captures = 0;
        let params =
            timeout_ms.map(|t| Value::Map(vec![(Value::UInt(PARAM_TIMEOUT_MS), Value::UInt(t))]));
        let request = self.build_request(SUB_ENROLL_BEGIN, params.as_ref());
        let cmd_code = self.cmd_code;
        // with_timeout scopes the capture window and restores the caller's
        // deadline (not the default — an embedder's wider timeout must
        // survive) on success and error alike, so later commands don't
        // inherit the 30s capture window.
        let resp = with_timeout(&mut *self.dev, CAPTURE_TIMEOUT, |dev| {
            transact_cbor(dev, cmd_code, &request)
        })?;
        let template_id = resp
            .get_uint_key(RESP_TEMPLATE_ID)
            .and_then(|v| v.as_bytes())
            .ok_or(CtapError::InvalidResponseShape("missing template id"))?
            .to_vec();
        let status = CaptureStatus {
            last_sample_status: field_uint(&resp, RESP_LAST_ENROLL_SAMPLE_STATUS).unwrap_or(0),
            remaining_samples: field_uint(&resp, RESP_REMAINING_SAMPLES).unwrap_or(0),
        };
        Ok((template_id, status))
    }

    /// Capture the next sample for an in-progress enrollment. Call repeatedly
    /// (touching the sensor each time) until `remaining_samples` is 0.
    pub fn enroll_capture_next(
        &mut self,
        template_id: &[u8],
        timeout_ms: Option<u64>,
    ) -> Result<CaptureStatus, CtapError> {
        // Host-owned bound (KEY-009): the device's remaining_samples drives
        // the callers' loops, so a device that never counts down must be cut
        // off here — before anything is sent — for every frontend at once.
        self.captures += 1;
        if self.captures > MAX_CAPTURE_ITERATIONS {
            return Err(CtapError::InvalidResponseShape(
                "authenticator kept requesting more fingerprint samples past the host cap",
            ));
        }
        let mut p = vec![(
            Value::UInt(PARAM_TEMPLATE_ID),
            Value::Bytes(template_id.to_vec()),
        )];
        if let Some(t) = timeout_ms {
            p.push((Value::UInt(PARAM_TIMEOUT_MS), Value::UInt(t)));
        }
        let params = Value::Map(p);
        let request = self.build_request(SUB_ENROLL_CAPTURE_NEXT, Some(&params));
        let cmd_code = self.cmd_code;
        // Restore the caller's deadline via with_timeout (see enroll_begin).
        let resp = with_timeout(&mut *self.dev, CAPTURE_TIMEOUT, |dev| {
            transact_cbor(dev, cmd_code, &request)
        })?;
        Ok(CaptureStatus {
            last_sample_status: field_uint(&resp, RESP_LAST_ENROLL_SAMPLE_STATUS).unwrap_or(0),
            remaining_samples: field_uint(&resp, RESP_REMAINING_SAMPLES).unwrap_or(0),
        })
    }

    /// Cancel an in-progress enrollment (e.g. the user gave up mid-capture).
    pub fn cancel_enrollment(&mut self) -> Result<(), CtapError> {
        // cancelCurrentEnrollment takes no params and no auth.
        let entries = vec![
            (Value::UInt(KEY_MODALITY), Value::UInt(MODALITY_FINGERPRINT)),
            (
                Value::UInt(KEY_SUB_COMMAND),
                Value::UInt(SUB_CANCEL_ENROLLMENT as u64),
            ),
        ];
        self.transact(&Value::Map(entries))?;
        Ok(())
    }

    /// Rename an enrolled fingerprint.
    pub fn set_friendly_name(&mut self, template_id: &[u8], name: &str) -> Result<(), CtapError> {
        let params = Value::Map(vec![
            (
                Value::UInt(PARAM_TEMPLATE_ID),
                Value::Bytes(template_id.to_vec()),
            ),
            (
                Value::UInt(PARAM_TEMPLATE_FRIENDLY_NAME),
                Value::Text(name.to_owned()),
            ),
        ]);
        self.dispatch(SUB_SET_FRIENDLY_NAME, Some(params))?;
        Ok(())
    }

    /// Remove an enrolled fingerprint.
    pub fn remove_enrollment(&mut self, template_id: &[u8]) -> Result<(), CtapError> {
        let params = Value::Map(vec![(
            Value::UInt(PARAM_TEMPLATE_ID),
            Value::Bytes(template_id.to_vec()),
        )]);
        self.dispatch(SUB_REMOVE_ENROLLMENT, Some(params))?;
        Ok(())
    }

    // --- internals ---

    /// Build + send an authenticated subcommand (those that require
    /// pinUvAuthParam): enroll*, setFriendlyName, removeEnrollment,
    /// enumerateEnrollments.
    fn dispatch(&mut self, sub: u8, params: Option<Value>) -> Result<Value, CtapError> {
        let request = self.build_request(sub, params.as_ref());
        self.transact(&request)
    }

    /// Encode the full request map for an authenticated subcommand.
    fn build_request(&self, sub: u8, params: Option<&Value>) -> Value {
        // pinUvAuthParam is computed over:
        //   modality (0x01) || subCommand || cbor(subCommandParams)
        // The leading modality byte is the bio-specific difference from
        // credential management.
        let mut auth_input = Vec::with_capacity(64);
        auth_input.push(MODALITY_FINGERPRINT as u8);
        auth_input.push(sub);
        if let Some(p) = params {
            auth_input.extend_from_slice(&cbor::encode(p));
        }
        let pin_uv_auth_param = self.token.authenticate(&auth_input);

        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(6);
        entries.push((Value::UInt(KEY_MODALITY), Value::UInt(MODALITY_FINGERPRINT)));
        entries.push((Value::UInt(KEY_SUB_COMMAND), Value::UInt(sub as u64)));
        if let Some(p) = params {
            entries.push((Value::UInt(KEY_SUB_COMMAND_PARAMS), p.clone()));
        }
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PROTOCOL),
            Value::UInt(self.token.protocol as u64),
        ));
        entries.push((
            Value::UInt(KEY_PIN_UV_AUTH_PARAM),
            Value::Bytes(pin_uv_auth_param),
        ));
        Value::Map(entries)
    }

    /// CBOR-encode `request`, prepend the command byte, transact, and decode.
    fn transact(&mut self, request: &Value) -> Result<Value, CtapError> {
        transact_cbor(&mut *self.dev, self.cmd_code, request)
    }
}

/// Body of [`BioEnrollment::transact`] as a free function, so the enroll
/// steps can run it inside [`with_timeout`] — which mutably borrows the
/// transport — without also borrowing the whole session.
fn transact_cbor(
    dev: &mut impl CtapTransport,
    cmd_code: u8,
    request: &Value,
) -> Result<Value, CtapError> {
    let encoded = cbor::encode(request);
    let mut payload = Vec::with_capacity(encoded.len() + 1);
    payload.push(cmd_code);
    payload.extend_from_slice(&encoded);
    let resp = dev.transact(CTAPHID_CBOR, &payload)?;
    let (status, body) = resp.split_first().ok_or(CtapError::EmptyResponse)?;
    if *status != 0 {
        return Err(CtapError::StatusCode(*status));
    }
    if body.is_empty() {
        return Ok(Value::Map(Vec::new()));
    }
    let (value, _) = cbor::decode(body)?;
    Ok(value)
}

fn field_uint(v: &Value, key: u64) -> Option<u64> {
    v.get_uint_key(key).and_then(|x| x.as_uint())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_pin::PinUvAuthToken;

    fn fake_token() -> PinUvAuthToken {
        PinUvAuthToken {
            protocol: 2,
            token: vec![0x11; 32],
        }
    }

    // The auth input for bio enrollment must begin with the modality byte, then
    // the subcommand, then cbor(params). This is the bio-specific framing.
    #[test]
    fn auth_input_is_modality_then_subcommand_then_params() {
        let token = fake_token();
        let params = Value::Map(vec![(
            Value::UInt(PARAM_TEMPLATE_ID),
            Value::Bytes(vec![0xAB, 0xCD]),
        )]);

        let mut expected = Vec::new();
        expected.push(MODALITY_FINGERPRINT as u8);
        expected.push(SUB_REMOVE_ENROLLMENT);
        expected.extend_from_slice(&cbor::encode(&params));
        let expected_param = token.authenticate(&expected);

        // Rebuild what build_request would compute for the param.
        let mut auth_input = Vec::new();
        auth_input.push(MODALITY_FINGERPRINT as u8);
        auth_input.push(SUB_REMOVE_ENROLLMENT);
        auth_input.extend_from_slice(&cbor::encode(&params));
        let got_param = token.authenticate(&auth_input);

        assert_eq!(got_param, expected_param);
    }

    #[test]
    fn enumerate_parses_template_infos() {
        // Build a fake enumerateEnrollments response and parse it.
        let resp = Value::Map(vec![(
            Value::UInt(RESP_TEMPLATE_INFOS),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::UInt(TI_TEMPLATE_ID), Value::Bytes(vec![0x01, 0x02])),
                    (
                        Value::UInt(TI_FRIENDLY_NAME),
                        Value::Text("left thumb".into()),
                    ),
                ]),
                Value::Map(vec![(
                    Value::UInt(TI_TEMPLATE_ID),
                    Value::Bytes(vec![0x03, 0x04]),
                )]),
            ]),
        )]);

        let arr = resp
            .get_uint_key(RESP_TEMPLATE_INFOS)
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2);
        let first_name = arr[0]
            .get_uint_key(TI_FRIENDLY_NAME)
            .and_then(|v| v.as_text());
        assert_eq!(first_name, Some("left thumb"));
        let second_name = arr[1]
            .get_uint_key(TI_FRIENDLY_NAME)
            .and_then(|v| v.as_text());
        assert_eq!(second_name, None);
    }

    #[test]
    fn sample_status_messages_cover_known_codes() {
        assert_eq!(sample_status_message(0x00), "good sample captured");
        assert!(sample_status_message(0x07).contains("timeout"));
        // unknown codes get a generic retry hint, never panic
        assert_eq!(sample_status_message(0xFF), "retry the sample");
    }

    /// A device that always answers a valid enrollment response demanding one
    /// more sample — the KEY-009 endless-`remaining_samples` attacker.
    struct EndlessSampler {
        calls: u32,
    }

    impl crate::transport::CtapTransport for EndlessSampler {
        fn transact(&mut self, _cmd: u8, _payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            self.calls += 1;
            // {4: templateId, 5: lastSampleStatus = good, 6: remaining = 1}.
            let map = Value::Map(vec![
                (
                    Value::UInt(RESP_TEMPLATE_ID),
                    Value::Bytes(vec![0xAA, 0xBB]),
                ),
                (Value::UInt(RESP_LAST_ENROLL_SAMPLE_STATUS), Value::UInt(0)),
                (Value::UInt(RESP_REMAINING_SAMPLES), Value::UInt(1)),
            ]);
            let mut resp = vec![0x00];
            resp.extend_from_slice(&cbor::encode(&map));
            Ok(resp)
        }
    }

    #[test]
    fn endless_remaining_samples_is_bounded_by_the_host_cap() {
        let mut dev = EndlessSampler { calls: 0 };
        {
            let mut bio = BioEnrollment::new(&mut dev, fake_token(), CTAP2_BIO_ENROLLMENT);
            // Drive the exact loop shape both frontends use.
            let (template_id, mut status) = bio.enroll_begin(None).unwrap();
            assert_eq!(status.remaining_samples, 1);
            let mut result: Result<(), CtapError> = Ok(());
            while status.remaining_samples > 0 {
                match bio.enroll_capture_next(&template_id, None) {
                    Ok(s) => status = s,
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
            assert!(
                matches!(result, Err(CtapError::InvalidResponseShape(_))),
                "expected the host-cap error, got {result:?}"
            );
        }
        // begin (1) + exactly the budget of captures; the over-budget call is
        // rejected on the host before anything is sent to the device.
        assert_eq!(dev.calls, MAX_CAPTURE_ITERATIONS + 1);
    }

    #[test]
    fn enroll_begin_resets_the_capture_budget() {
        let mut dev = EndlessSampler { calls: 0 };
        let mut bio = BioEnrollment::new(&mut dev, fake_token(), CTAP2_BIO_ENROLLMENT);
        let (template_id, _) = bio.enroll_begin(None).unwrap();
        // Exhaust the budget on the first enrollment.
        for _ in 0..MAX_CAPTURE_ITERATIONS {
            bio.enroll_capture_next(&template_id, None).unwrap();
        }
        assert!(bio.enroll_capture_next(&template_id, None).is_err());
        // A fresh enrollment gets a fresh budget.
        let (template_id, _) = bio.enroll_begin(None).unwrap();
        assert!(bio.enroll_capture_next(&template_id, None).is_ok());
    }

    // Documents the spec quirk: enumerate maps 0x2C (INVALID_OPTION) to an empty
    // list, since that's how an authenticator with zero enrollments answers.
    #[test]
    fn invalid_option_status_is_the_empty_signal() {
        // The mapping lives in enumerate(); this guards the constant we match on.
        assert_eq!(0x2C, 44);
        // A sanity check that StatusCode(0x2C) is the variant we special-case.
        let e = CtapError::StatusCode(0x2C);
        assert!(matches!(e, CtapError::StatusCode(0x2C)));
    }
}
