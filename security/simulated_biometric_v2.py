"""Controlled software biometric model for the v2 thesis experiment.

It does not represent physical sensor acquisition. It generates reproducible
feature vectors with genuine/impostor variation, encrypts enrolled templates
with AES-256-GCM, and exposes scores for ROC, FAR, FRR, and EER analysis.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import random
import struct
from typing import Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config.runtime_security import strong_secret_or_none


MODE = "software_simulated_v2"
SAMPLE_PREFIX = "simv2:"
TEMPLATE_PREFIX = "simv2-aesgcm"
VECTOR_SIZE = 64
DEFAULT_THRESHOLD = 0.92
GENUINE_NOISE_SIGMA = 0.035


def _secret(name: str) -> bytes:
    value = strong_secret_or_none(os.getenv(name))
    if value is None:
        raise RuntimeError(
            "%s must be a non-placeholder secret of at least 32 characters" % name
        )
    return value.encode("utf-8")


def _normalized_username(username: str) -> str:
    value = str(username or "").strip().casefold()
    if not value:
        raise ValueError("Username is required")
    return value


def _unit(vector: Iterable[float]) -> List[float]:
    values = [float(value) for value in vector]
    if len(values) != VECTOR_SIZE or not all(math.isfinite(value) for value in values):
        raise ValueError("Biometric vector has an invalid shape or value")
    norm = math.sqrt(sum(value * value for value in values))
    if norm <= 1e-12:
        raise ValueError("Biometric vector has zero magnitude")
    return [value / norm for value in values]


def _seed(label: str) -> int:
    digest = hmac.new(
        _secret("EXPERIMENT_MASTER_SECRET"), label.encode("utf-8"), hashlib.sha256
    ).digest()
    return int.from_bytes(digest[:8], "big")


def reference_vector(username: str) -> List[float]:
    """Return a stable latent identity vector for one experiment user."""
    normalized = _normalized_username(username)
    rng = random.Random(_seed("biometric-reference|" + normalized))
    return _unit(rng.gauss(0.0, 1.0) for _ in range(VECTOR_SIZE))


def simulated_probe(
    username: str,
    *,
    probe_index: int = 0,
    genuine: bool = True,
    impostor_username: Optional[str] = None,
) -> str:
    """Create a deterministic genuine or impostor feature-vector sample."""
    normalized = _normalized_username(username)
    identity = normalized if genuine else _normalized_username(impostor_username or "impostor")
    baseline = reference_vector(identity)
    rng = random.Random(
        _seed(
            "biometric-probe|%s|%s|%s|%s"
            % (normalized, identity, int(probe_index), int(bool(genuine)))
        )
    )
    sigma = GENUINE_NOISE_SIGMA if genuine else 0.02
    return encode_sample(
        _unit(value + rng.gauss(0.0, sigma) for value in baseline)
    )


def encode_sample(vector: Iterable[float]) -> str:
    packed = struct.pack("!%sf" % VECTOR_SIZE, *_unit(vector))
    encoded = base64.urlsafe_b64encode(packed).decode("ascii").rstrip("=")
    return SAMPLE_PREFIX + encoded


def decode_sample(sample: str) -> List[float]:
    text = str(sample or "").strip()
    if not text.startswith(SAMPLE_PREFIX):
        raise ValueError("Expected a simv2 biometric sample")
    encoded = text[len(SAMPLE_PREFIX):]
    raw = base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))
    if len(raw) != VECTOR_SIZE * 4:
        raise ValueError("Biometric sample length is invalid")
    return _unit(struct.unpack("!%sf" % VECTOR_SIZE, raw))


def cosine_similarity(left: Iterable[float], right: Iterable[float]) -> float:
    first, second = _unit(left), _unit(right)
    return max(-1.0, min(1.0, sum(a * b for a, b in zip(first, second))))


def _encryption_key() -> bytes:
    return hashlib.sha256(
        b"sdnmfa-v2-biometric-template\x00" + _secret("BIOMETRIC_PEPPER")
    ).digest()


def encrypt_template(username: str, vector: Iterable[float]) -> str:
    normalized = _normalized_username(username)
    plaintext = json.dumps(
        {"version": 2, "vector": _unit(vector)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(_encryption_key()).encrypt(
        nonce, plaintext, normalized.encode("utf-8")
    )
    return "%s$%s$%s" % (
        TEMPLATE_PREFIX,
        base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("="),
    )


def decrypt_template(username: str, stored: str) -> List[float]:
    normalized = _normalized_username(username)
    prefix, nonce_text, ciphertext_text = str(stored or "").split("$", 2)
    if prefix != TEMPLATE_PREFIX:
        raise ValueError("Unsupported biometric template format")
    nonce = base64.urlsafe_b64decode(nonce_text + ("=" * (-len(nonce_text) % 4)))
    ciphertext = base64.urlsafe_b64decode(
        ciphertext_text + ("=" * (-len(ciphertext_text) % 4))
    )
    if len(nonce) != 12:
        raise ValueError("Biometric template nonce is invalid")
    plaintext = AESGCM(_encryption_key()).decrypt(
        nonce, ciphertext, normalized.encode("utf-8")
    )
    payload = json.loads(plaintext.decode("utf-8"))
    if payload.get("version") != 2:
        raise ValueError("Unsupported biometric template version")
    return _unit(payload["vector"])


def score_probe(username: str, stored: str, sample: str) -> float:
    return cosine_similarity(decrypt_template(username, stored), decode_sample(sample))


def verify_probe(
    username: str,
    stored: str,
    sample: str,
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> Tuple[bool, float]:
    score = score_probe(username, stored, sample)
    return score >= float(threshold), score
