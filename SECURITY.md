# Security policy

Please report security issues in this verifier, or any doubt about a
Lapidarc signature or public key, privately to **security@lapidarc.com**.

Please do not open a public issue for a suspected vulnerability.

Include, if you can: what you ran, what you expected, what happened, and the
SHA-256 of the files involved (not the files themselves if they are
confidential). We will acknowledge your report and keep you informed while we
look into it.

## Checking the public key

The only public key this repository ships is `lapidarc-public-key.bin`
(raw, 1952 bytes) and the same key as `lapidarc-public-key.pem`. Its
SHA-256 fingerprint is listed in `README.md`. If the fingerprint of the key
you are using differs, do not rely on the result and contact
security@lapidarc.com.
