"""
utils/functional_encryption.py
------------------------------
Public-key functional encryption helpers for TrustGrid.

This module wraps the FeDamgard scheme from the `mife` package and keeps
serialization details out of the Flask routes. The public key (mpk) is used
for encryption, while the master secret key (msk) is kept server-side and used
only to derive function keys.
"""

from __future__ import annotations

import json
import os
from typing import Iterable

from mife.data.zmod import Zmod
from mife.single.damgard import FeDamgard, _FeDamgard_C, _FeDamgard_MK

from config import (
    FE_DECRYPT_BOUND,
    FE_FRAUD_SCORE_THRESHOLD,
    FE_MASTER_KEY_PATH,
    FE_PUBLIC_KEY_PATH,
    FE_SCORE_WEIGHTS,
    FE_VECTOR_DIM,
    FRAUD_AMOUNT_THRESHOLD,
    FRAUD_HOUR_THRESHOLD,
)


def ensure_fe_keys(force: bool = False) -> None:
    """Generate and persist FE master/public keys if they do not exist."""
    if not force and os.path.isfile(FE_MASTER_KEY_PATH) and os.path.isfile(FE_PUBLIC_KEY_PATH):
        return

    os.makedirs(os.path.dirname(FE_MASTER_KEY_PATH), exist_ok=True)

    master_key = FeDamgard.generate(FE_VECTOR_DIM)
    public_key = master_key.get_public_key()

    with open(FE_MASTER_KEY_PATH, "w", encoding="utf-8") as handle:
        json.dump(master_key.export(), handle)
    with open(FE_PUBLIC_KEY_PATH, "w", encoding="utf-8") as handle:
        json.dump(public_key.export(), handle)


def load_master_key() -> _FeDamgard_MK:
    """Load the persisted FE master secret key (msk)."""
    ensure_fe_keys()
    with open(FE_MASTER_KEY_PATH, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _master_key_from_payload(payload)


def load_public_key() -> _FeDamgard_MK:
    """Load the persisted FE master public key (mpk)."""
    ensure_fe_keys()
    with open(FE_PUBLIC_KEY_PATH, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return _master_key_from_payload(payload)


def export_public_key_payload() -> dict:
    """Return the serialized public key payload for API consumers."""
    ensure_fe_keys()
    with open(FE_PUBLIC_KEY_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def encode_transaction_vector(amount, time_str) -> list[int]:
    """
    Convert a transaction into a bounded FE vector.

    Vector layout:
    - index 0: high_amount_flag
    - index 1: night_transaction_flag
    """
    high_amount = 0
    night_flag = 0

    try:
        high_amount = int(float(amount) > FRAUD_AMOUNT_THRESHOLD)
    except (TypeError, ValueError):
        high_amount = 0

    try:
        hour = int(str(time_str).split(":")[0].split(" ")[-1])
        night_flag = int(hour < FRAUD_HOUR_THRESHOLD)
    except Exception:
        night_flag = 0

    return [high_amount, night_flag]


def encrypt_vector(vector: Iterable[int], public_key: _FeDamgard_MK | None = None) -> _FeDamgard_C:
    """Encrypt a bounded transaction vector using the public key (mpk)."""
    if public_key is None:
        public_key = load_public_key()
    return FeDamgard.encrypt(list(vector), public_key)


def derive_function_key(function_vector: Iterable[int] | None = None, master_key: _FeDamgard_MK | None = None):
    """Derive a function key from the master secret key (msk)."""
    if master_key is None:
        master_key = load_master_key()
    return FeDamgard.keygen(list(function_vector or FE_SCORE_WEIGHTS), master_key)


def decrypt_inner_product(
    ciphertext: _FeDamgard_C,
    function_key,
    public_key: _FeDamgard_MK | None = None,
    bound: tuple[int, int] | None = None,
) -> int:
    """Decrypt only the allowed inner-product result."""
    if public_key is None:
        public_key = load_public_key()
    return FeDamgard.decrypt(ciphertext, public_key, function_key, bound or FE_DECRYPT_BOUND)


def serialize_ciphertext(ciphertext: _FeDamgard_C) -> str:
    """Serialize ciphertext for database storage."""
    return json.dumps(ciphertext.export(), separators=(",", ":"))


def deserialize_ciphertext(serialized: str, public_key: _FeDamgard_MK | None = None) -> _FeDamgard_C:
    """Deserialize ciphertext from database storage."""
    if public_key is None:
        public_key = load_public_key()
    payload = json.loads(serialized)
    return _ciphertext_from_payload(payload, public_key)


def preview_ciphertext(serialized: str, chars: int = 18) -> str:
    """Return a short preview string suitable for logs."""
    if not serialized:
        return "pending..."
    return serialized[:chars] + "..."


def is_fraud_score(score: int) -> bool:
    """Convert a decrypted FE score into a fraud decision."""
    return score >= FE_FRAUD_SCORE_THRESHOLD


def _master_key_from_payload(payload: dict) -> _FeDamgard_MK:
    group = _group_from_payload(payload["F"])
    g = _elem_from_payload(group, payload["g"])
    h = _elem_from_payload(group, payload["h"])
    mpk = [_elem_from_payload(group, item) for item in payload["mpk"]]
    msk = payload.get("msk")
    if msk is not None:
        msk = [tuple(pair) for pair in msk]
    return _FeDamgard_MK(g, h, int(payload["n"]), group, mpk=mpk, msk=msk)


def _ciphertext_from_payload(payload: dict, public_key: _FeDamgard_MK) -> _FeDamgard_C:
    return _FeDamgard_C(
        _elem_from_payload(public_key.F, payload["g_r"]),
        _elem_from_payload(public_key.F, payload["h_r"]),
        [_elem_from_payload(public_key.F, item) for item in payload["c"]],
    )


def _group_from_payload(payload: dict):
    if payload.get("type") != "Zmod":
        raise ValueError(f"Unsupported FE group payload: {payload!r}")
    return Zmod(int(payload["modulus"]))


def _elem_from_payload(group, payload: dict):
    return group(int(payload["val"]))
