#!/usr/bin/env python3
# Copyright 2026 Lapidarc
# SPDX-License-Identifier: Apache-2.0
"""Verify a Lapidarc Codex signature.

A Lapidarc Codex is a PDF with a detached signature file next to it
(``<name>.pdf.sig``). The signature is ML-DSA-65 (FIPS 204) over the exact
bytes of the PDF file, with no hashing or encoding step in between. If even
one byte of the PDF changes, the signature no longer verifies.

Usage:
    python verify.py document.pdf document.pdf.sig
    python verify.py document.pdf document.pdf.sig --key lapidarc-public-key.pem

Exit codes:
    0  signature is valid for this PDF and this public key
    1  signature is NOT valid (the file was changed, or the signature or key
       does not belong to it)
    2  usage or input error (missing file, unreadable key, ...)
"""
import argparse
import base64
import hashlib
import os
import sys

ALGORITHM = "ML-DSA-65"
PUBLIC_KEY_LEN = 1952          # ML-DSA-65 public key, FIPS 204
SIGNATURE_LEN = 3309           # ML-DSA-65 signature, FIPS 204
# DER prefix of a SubjectPublicKeyInfo carrying an ML-DSA-65 key
# (OID 2.16.840.1.101.3.4.3.18), followed by the 1952 raw bytes.
SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")

DEFAULT_KEY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "lapidarc-public-key.bin")


class InputError(Exception):
    pass


def load_public_key(path):
    """Return the 1952 raw public-key bytes from a raw .bin, a DER
    SubjectPublicKeyInfo, or a PEM "PUBLIC KEY" file."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise InputError(f"cannot read public key {path}: {e.strerror}")

    if data.lstrip().startswith(b"-----BEGIN"):
        lines = data.decode("ascii", "replace").strip().splitlines()
        if not (lines[0].strip() == "-----BEGIN PUBLIC KEY-----"
                and lines[-1].strip() == "-----END PUBLIC KEY-----"):
            raise InputError(f"{path}: expected a PEM 'PUBLIC KEY' block")
        try:
            data = base64.b64decode("".join(l.strip() for l in lines[1:-1]),
                                    validate=True)
        except ValueError:
            raise InputError(f"{path}: PEM body is not valid base64")

    if len(data) == PUBLIC_KEY_LEN:
        return data
    if len(data) == len(SPKI_PREFIX) + PUBLIC_KEY_LEN and data.startswith(SPKI_PREFIX):
        return data[len(SPKI_PREFIX):]
    raise InputError(
        f"{path}: not an {ALGORITHM} public key "
        f"(got {len(data)} bytes, expected {PUBLIC_KEY_LEN} raw or an "
        f"{ALGORITHM} SubjectPublicKeyInfo)")


def read_file(path, what):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise InputError(f"cannot read {what} {path}: {e.strerror}")


def verify_bytes(message, signature, public_key):
    """True if `signature` is a valid ML-DSA-65 signature of `message`."""
    import oqs
    with oqs.Signature(ALGORITHM) as verifier:
        try:
            return bool(verifier.verify(message, signature, public_key))
        except Exception:
            # liboqs may raise on malformed input instead of returning False.
            return False


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Verify the ML-DSA-65 signature of a Lapidarc Codex PDF.")
    p.add_argument("pdf", help="the signed PDF")
    p.add_argument("sig", help="its detached signature file (usually <pdf>.sig)")
    p.add_argument("--key", default=DEFAULT_KEY,
                   help="public key: raw .bin, or PEM/DER SubjectPublicKeyInfo "
                        "(default: lapidarc-public-key.bin next to this script)")
    args = p.parse_args(argv)

    try:
        public_key = load_public_key(args.key)
        pdf = read_file(args.pdf, "PDF")
        sig = read_file(args.sig, "signature")
    except InputError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    try:
        import oqs  # noqa: F401
    except ImportError:
        print("ERROR: liboqs-python is not installed (see README).", file=sys.stderr)
        return 2

    print(f"PDF:          {args.pdf}")
    print(f"PDF SHA-256:  {hashlib.sha256(pdf).hexdigest()}")
    print(f"Key SHA-256:  {hashlib.sha256(public_key).hexdigest()}")
    print(f"Algorithm:    {ALGORITHM}")

    if len(sig) == SIGNATURE_LEN and verify_bytes(pdf, sig, public_key):
        print("VALID: this PDF is exactly the file that was signed with this key.")
        return 0
    print("INVALID: this PDF does not match the signature. It may have been "
          "altered, or the signature or key does not belong to it. "
          "Do not trust it as an authentic Lapidarc Codex.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
