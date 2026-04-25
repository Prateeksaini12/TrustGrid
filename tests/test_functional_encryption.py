"""
tests/test_functional_encryption.py
-----------------------------------
Unit tests for TrustGrid's FE helper module.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ["TRUSTGRID_FE_KEY_DIR"] = tempfile.mkdtemp()

from utils.functional_encryption import (
    decrypt_inner_product,
    derive_function_key,
    encode_transaction_vector,
    encrypt_vector,
    ensure_fe_keys,
    is_fraud_score,
    load_public_key,
)


class TestFunctionalEncryption:
    def test_encode_transaction_vector(self):
        assert encode_transaction_vector(15000, "02:00") == [1, 1]
        assert encode_transaction_vector(50, "14:30") == [0, 0]

    def test_encrypt_and_decrypt_score(self):
        ensure_fe_keys(force=True)
        public_key = load_public_key()
        function_key = derive_function_key()

        ciphertext = encrypt_vector([1, 0], public_key)
        score = decrypt_inner_product(ciphertext, function_key, public_key)

        assert score == 1
        assert is_fraud_score(score) is True

    def test_safe_transaction_stays_below_threshold(self):
        ensure_fe_keys(force=True)
        public_key = load_public_key()
        function_key = derive_function_key()

        ciphertext = encrypt_vector([0, 0], public_key)
        score = decrypt_inner_product(ciphertext, function_key, public_key)

        assert score == 0
        assert is_fraud_score(score) is False
