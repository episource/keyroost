- **The PIV pane's refresh no longer re-reads the same card objects.** It
  gathered each slot's key algorithm, certificate Subject DN and PIN/touch
  policy through separate transport calls, so every slot's certificate was
  fetched two or three times and GET METADATA twice. A new
  `PivSession::status_detailed` reads each slot's certificate object and
  GET METADATA exactly once and shares them across all three, roughly
  halving the refresh's APDU traffic. A slot whose certificate object
  carries no `70` TLV now reports as empty rather than "cert present",
  matching what `piv export-cert` already reported for it. `cert_len` in
  `piv status` (and `--json`) now reports the certificate's DER length
  rather than the card's object size, so it is a few bytes smaller than
  before. Contributed by @episource. ([#119])
