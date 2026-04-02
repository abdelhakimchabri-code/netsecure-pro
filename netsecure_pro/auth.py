from __future__ import annotations

import hashlib
import hmac
import os
import re

PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 260_000
LEGACY_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    ).hex()
    return f"{PBKDF2_ALGORITHM}${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False

    if stored_hash.startswith(f"{PBKDF2_ALGORITHM}$"):
        try:
            _, iteration_text, salt, expected_hash = stored_hash.split("$", maxsplit=3)
            iterations = int(iteration_text)
            candidate_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt),
                iterations,
            ).hex()
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(candidate_hash, expected_hash)

    if LEGACY_SHA256_PATTERN.fullmatch(stored_hash):
        candidate_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(candidate_hash, stored_hash)

    return False


def password_needs_rehash(stored_hash: str) -> bool:
    return not stored_hash.startswith(f"{PBKDF2_ALGORITHM}$")


def validate_password_policy(password: str) -> list[str]:
    errors: list[str] = []
    if len(password) < 8:
        errors.append("Use at least 8 characters.")
    if password.lower() == password:
        errors.append("Add at least one uppercase letter.")
    if password.upper() == password:
        errors.append("Add at least one lowercase letter.")
    if not any(character.isdigit() for character in password):
        errors.append("Add at least one number.")
    return errors
