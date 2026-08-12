//! Transport abstraction for CTAP2 commands.
//!
//! Every CTAP command in this crate is expressed as a single logical exchange:
//! send a command byte plus a CBOR payload, get back a response byte string
//! (the first byte is the CTAP2 status, the rest is CBOR). Historically that
//! exchange went only over CTAP-HID (USB). [`CtapTransport`] lifts it into a
//! trait so the same command code can run over any link that can carry a CTAP
//! message — in particular PC/SC, which is how both **NFC** and **contact**
//! smart-card readers present a key (see `ctap_pcsc` in `keyroost-transport`).
//!
//! The trait is deliberately tiny: one method, mirroring
//! `CtapHidDevice::transact`. Backends own all the link-specific framing —
//! CTAP-HID channels and continuation packets on one side, ISO 7816 `NFCCTAP_MSG`
//! APDUs with command chaining and `GET RESPONSE` reassembly on the other — and
//! present the command layer with the same clean `Vec<u8>` it always had.

use crate::cmd::CtapError;

/// Forwarding impl so a `&mut T` (and, by extension, the `&mut dyn` produced
/// from a boxed transport) can be passed where `impl CtapTransport` is expected.
impl<T: CtapTransport + ?Sized> CtapTransport for &mut T {
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
        (**self).transact(cmd, payload)
    }
    fn set_timeout(&mut self, timeout: std::time::Duration) {
        (**self).set_timeout(timeout);
    }
    fn read_timeout(&self) -> std::time::Duration {
        (**self).read_timeout()
    }
    fn set_cancel_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        (**self).set_cancel_flag(flag);
    }
}

/// Forwarding impl so a `Box<dyn CtapTransport>` is itself a `CtapTransport`,
/// letting a runtime-selected backend (HID vs PC/SC) be used with the generic
/// command functions that take `&mut impl CtapTransport`.
impl CtapTransport for Box<dyn CtapTransport> {
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
        (**self).transact(cmd, payload)
    }
    fn set_timeout(&mut self, timeout: std::time::Duration) {
        (**self).set_timeout(timeout);
    }
    fn read_timeout(&self) -> std::time::Duration {
        (**self).read_timeout()
    }
    fn set_cancel_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        (**self).set_cancel_flag(flag);
    }
}

/// Run `f` with the transport's read timeout temporarily set to `timeout`,
/// restoring the caller's previous deadline afterwards — on the closure's
/// success and failure alike. Every long, user-present operation (a reset, a
/// fingerprint capture waiting on a touch) must scope its wide window through
/// this rather than hand-rolling save/set/restore: a caller that forgets the
/// restore leaks its window into every later command on the device, making
/// unrelated error paths take that long to surface.
///
/// The previous value comes from [`CtapTransport::read_timeout`], not the
/// default, so an embedder's wider configured timeout survives. Not
/// panic-safe: a panicking closure skips the restore, exactly like the
/// hand-rolled sequences this replaces (CTAP command code returns `Result`s,
/// it doesn't panic).
pub fn with_timeout<T, R>(
    dev: &mut T,
    timeout: std::time::Duration,
    f: impl FnOnce(&mut T) -> R,
) -> R
where
    T: CtapTransport + ?Sized,
{
    let prev = dev.read_timeout();
    dev.set_timeout(timeout);
    let out = f(dev);
    dev.set_timeout(prev);
    out
}
///
/// `cmd` is the CTAP-HID command byte the command layer would historically pass
/// (e.g. `CTAPHID_CBOR`). Non-HID transports interpret it as needed — the PC/SC
/// backend, for instance, treats `CTAPHID_CBOR` as "wrap this payload in an
/// `NFCCTAP_MSG` APDU" and ignores HID-only commands like `CTAPHID_INIT`.
pub trait CtapTransport {
    /// Perform one command/response exchange and return the raw response bytes
    /// (CTAP2 status byte followed by the CBOR body).
    fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError>;

    /// Extend the read timeout for a long, user-present operation (a reset or a
    /// fingerprint-enrollment capture that waits for a touch).
    ///
    /// HID overrides this to widen its report-read deadline. Transports that
    /// manage their own timeouts (PC/SC drivers apply their own card timeouts)
    /// can leave the default no-op.
    fn set_timeout(&mut self, _timeout: std::time::Duration) {}

    /// The read timeout currently in effect, so a long-window operation (reset,
    /// fingerprint capture) can save the caller's configured value and restore
    /// *it* afterwards instead of clobbering it back to the default. Transports
    /// whose `set_timeout` is a no-op just report the HID default.
    fn read_timeout(&self) -> std::time::Duration {
        crate::hid::DEFAULT_READ_TIMEOUT
    }

    /// Wire in a cooperative cancel flag so a capture blocked waiting for a touch
    /// can abort promptly when the user cancels.
    ///
    /// HID checks this between KEEPALIVE frames. PC/SC has no equivalent hook in
    /// its blocking transmit, so the default is a no-op (a reader-attached
    /// enrollment simply runs to its own timeout if not completed).
    fn set_cancel_flag(&mut self, _flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Records every set_timeout call so tests can assert the guard's exact
    /// set-then-restore sequence, not just the final state.
    struct MockTransport {
        timeout: Duration,
        set_calls: Vec<Duration>,
    }

    impl MockTransport {
        fn new(initial: Duration) -> Self {
            MockTransport {
                timeout: initial,
                set_calls: Vec::new(),
            }
        }
    }

    impl CtapTransport for MockTransport {
        fn transact(&mut self, _cmd: u8, _payload: &[u8]) -> Result<Vec<u8>, CtapError> {
            Ok(vec![0x00])
        }
        fn set_timeout(&mut self, timeout: Duration) {
            self.set_calls.push(timeout);
            self.timeout = timeout;
        }
        fn read_timeout(&self) -> Duration {
            self.timeout
        }
    }

    /// `reset` must stay transport-generic: the in-place card reset (issue
    /// #84) sends it over a PC/SC transport, and any drift toward a HID-only
    /// assumption in the command layer would sever that path. Pins the exact
    /// wire shape: one CTAPHID_CBOR transact carrying the bare CTAP2_RESET
    /// byte, success on a 0x00 status.
    #[test]
    fn reset_is_one_bare_cbor_transact_on_any_transport() {
        struct Recorder {
            timeout: Duration,
            calls: Vec<(u8, Vec<u8>)>,
        }
        impl CtapTransport for Recorder {
            fn transact(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, CtapError> {
                self.calls.push((cmd, payload.to_vec()));
                Ok(vec![0x00])
            }
            fn set_timeout(&mut self, timeout: Duration) {
                self.timeout = timeout;
            }
            fn read_timeout(&self) -> Duration {
                self.timeout
            }
        }
        let mut dev = Recorder {
            timeout: Duration::from_secs(1),
            calls: Vec::new(),
        };
        crate::cmd::reset(&mut dev).expect("0x00 status is success");
        assert_eq!(
            dev.calls,
            vec![(crate::hid::CTAPHID_CBOR, vec![crate::cmd::CTAP2_RESET])]
        );
    }

    #[test]
    fn with_timeout_restores_callers_deadline_on_ok() {
        // The restore target is the *caller's* value (7s here), not the
        // default — an embedder's widened timeout must survive.
        let caller = Duration::from_secs(7);
        let wide = Duration::from_secs(30);
        let mut dev = MockTransport::new(caller);
        let out: Result<u8, CtapError> = with_timeout(&mut dev, wide, |d| {
            assert_eq!(d.read_timeout(), wide, "closure runs under the wide window");
            Ok(42)
        });
        assert_eq!(out.unwrap(), 42);
        assert_eq!(dev.read_timeout(), caller);
        assert_eq!(dev.set_calls, vec![wide, caller]);
    }

    #[test]
    fn with_timeout_restores_callers_deadline_on_err() {
        // A failed transaction must not leak the wide window into later
        // commands (that made unrelated error paths take 30s to surface).
        let caller = Duration::from_secs(7);
        let wide = Duration::from_secs(30);
        let mut dev = MockTransport::new(caller);
        let out: Result<u8, CtapError> =
            with_timeout(&mut dev, wide, |_| Err(CtapError::EmptyResponse));
        assert!(out.is_err());
        assert_eq!(dev.read_timeout(), caller);
        assert_eq!(dev.set_calls, vec![wide, caller]);
    }
}
