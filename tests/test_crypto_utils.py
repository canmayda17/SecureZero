from __future__ import annotations

import unittest

from crypto_utils import (
    aesgcm_decrypt,
    aesgcm_encrypt,
    derive_session_keys,
    generate_private_key,
    rsa_decrypt,
    rsa_encrypt,
    rsa_sign,
    rsa_verify,
)


class CryptoUtilsTests(unittest.TestCase):
    def test_rsa_sign_and_verify_round_trip(self):
        key = generate_private_key()
        message = b"securezero"
        signature = rsa_sign(key, message)
        self.assertTrue(rsa_verify(key.public_key(), signature, message))
        self.assertFalse(rsa_verify(key.public_key(), signature, b"changed"))

    def test_rsa_oaep_wrap_round_trip(self):
        key = generate_private_key()
        wrapped = rsa_encrypt(key.public_key(), b"x" * 32)
        self.assertEqual(rsa_decrypt(key, wrapped), b"x" * 32)

    def test_aesgcm_round_trip_with_aad(self):
        key = b"k" * 32
        nonce, ciphertext = aesgcm_encrypt(key, b"payload", b"aad")
        self.assertEqual(aesgcm_decrypt(key, nonce, ciphertext, b"aad"), b"payload")

    def test_session_key_derivation_is_directional(self):
        premaster = b"p" * 32
        c_nonce = b"c" * 32
        s_nonce = b"s" * 32
        c2s, s2c, session_id = derive_session_keys(premaster, c_nonce, s_nonce)
        self.assertNotEqual(c2s, s2c)
        self.assertEqual(len(c2s), 32)
        self.assertEqual(len(s2c), 32)
        self.assertEqual(len(session_id), 32)


if __name__ == "__main__":
    unittest.main()
