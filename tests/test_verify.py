# Copyright 2026 Lapidarc
# SPDX-License-Identifier: Apache-2.0
"""Tests for verify.py.

Every key used here is a throwaway keypair generated inside the test run.
No real signing key is used or needed. Run with:  python -m unittest discover -s tests
"""
import base64
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

import oqs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import verify  # noqa: E402

VERIFY = os.path.join(ROOT, "verify.py")


def run(*args):
    return subprocess.run([sys.executable, VERIFY, *args],
                          capture_output=True, text=True)


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.tmp.name
        with oqs.Signature("ML-DSA-65") as signer:
            cls.pub = signer.generate_keypair()
            cls.pdf_bytes = b"%PDF-1.7\n" + os.urandom(4096) + b"\n%%EOF\n"
            cls.sig_bytes = signer.sign(cls.pdf_bytes)
        with oqs.Signature("ML-DSA-65") as other:
            cls.other_pub = other.generate_keypair()

        def write(name, data):
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(data)
            return p

        cls.pdf = write("doc.pdf", cls.pdf_bytes)
        cls.sig = write("doc.pdf.sig", cls.sig_bytes)
        cls.key_bin = write("key.bin", cls.pub)
        cls.other_key = write("other.bin", cls.other_pub)
        der = verify.SPKI_PREFIX + cls.pub
        cls.key_der = write("key.der", der)
        pem = ("-----BEGIN PUBLIC KEY-----\n"
               + "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
               + "\n-----END PUBLIC KEY-----\n")
        cls.key_pem = write("key.pem", pem.encode())
        tampered = bytearray(cls.pdf_bytes)
        tampered[len(tampered) // 2] ^= 0x01
        cls.tampered = write("tampered.pdf", bytes(tampered))
        cls.appended = write("appended.pdf", cls.pdf_bytes + b"\n")
        bad_sig = bytearray(cls.sig_bytes)
        bad_sig[100] ^= 0x80
        cls.bad_sig = write("bad.sig", bytes(bad_sig))
        cls.short_sig = write("short.sig", cls.sig_bytes[:-1])
        cls.wrong_size_key = write("wrong.key", b"\0" * 4032)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_sizes_match_fips204(self):
        self.assertEqual(len(self.pub), verify.PUBLIC_KEY_LEN)
        self.assertEqual(len(self.sig_bytes), verify.SIGNATURE_LEN)

    def test_valid_raw_key(self):
        r = run(self.pdf, self.sig, "--key", self.key_bin)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VALID", r.stdout)

    def test_valid_pem_key(self):
        self.assertEqual(run(self.pdf, self.sig, "--key", self.key_pem).returncode, 0)

    def test_valid_der_key(self):
        self.assertEqual(run(self.pdf, self.sig, "--key", self.key_der).returncode, 0)

    def test_one_byte_change_is_invalid(self):
        r = run(self.tampered, self.sig, "--key", self.key_bin)
        self.assertEqual(r.returncode, 1)
        self.assertIn("INVALID", r.stdout)

    def test_appended_byte_is_invalid(self):
        self.assertEqual(run(self.appended, self.sig, "--key", self.key_bin).returncode, 1)

    def test_modified_signature_is_invalid(self):
        self.assertEqual(run(self.pdf, self.bad_sig, "--key", self.key_bin).returncode, 1)

    def test_truncated_signature_is_invalid(self):
        self.assertEqual(run(self.pdf, self.short_sig, "--key", self.key_bin).returncode, 1)

    def test_wrong_key_is_invalid(self):
        self.assertEqual(run(self.pdf, self.sig, "--key", self.other_key).returncode, 1)

    def test_non_public_key_file_is_rejected(self):
        r = run(self.pdf, self.sig, "--key", self.wrong_size_key)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not an ML-DSA-65 public key", r.stderr)

    def test_missing_file_is_error(self):
        r = run(self.pdf + ".nope", self.sig, "--key", self.key_bin)
        self.assertEqual(r.returncode, 2)

    def test_shipped_key_files_agree(self):
        raw = verify.load_public_key(os.path.join(ROOT, "lapidarc-public-key.bin"))
        pem = verify.load_public_key(os.path.join(ROOT, "lapidarc-public-key.pem"))
        self.assertEqual(len(raw), verify.PUBLIC_KEY_LEN)
        self.assertEqual(raw, pem)


if __name__ == "__main__":
    unittest.main()
