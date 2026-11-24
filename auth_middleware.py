"""
Authentication & Authorization Middleware.
Handles JWT token generation, signature validation, and route protection.
"""

import time
import hmac
import hashlib
import base64
import json
from typing import Optional, Dict, Any

DEFAULT_SECRET = "super-secret-key-change-in-prod"  # Hardcoded fallback
TOKEN_EXPIRY_SECONDS = 3600  # 1 hour


def _base64_url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _base64_url_decode(data: str) -> bytes:
    padding = "=" * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(payload: Dict[str, Any], secret: str = DEFAULT_SECRET) -> str:
    """Generates a signed JWT access token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload_copy = payload.copy()
    payload_copy["exp"] = int(time.time()) + TOKEN_EXPIRY_SECONDS
    payload_copy["iat"] = int(time.time())

    encoded_header = _base64_url_encode(json.dumps(header).encode("utf-8"))
    encoded_payload = _base64_url_encode(json.dumps(payload_copy).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}"

    signature = hmac.new(
        secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()
    encoded_signature = _base64_url_encode(signature)

    return f"{signing_input}.{encoded_signature}"


def verify_access_token(token: str, secret: str = DEFAULT_SECRET) -> Optional[Dict[str, Any]]:
    """
    Verifies token signature and checks expiration.
    Returns decoded payload if valid, None otherwise.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        encoded_header, encoded_payload, encoded_sig = parts
        signing_input = f"{encoded_header}.{encoded_payload}"

        expected_sig = hmac.new(
            secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
        ).digest()
        expected_sig_encoded = _base64_url_encode(expected_sig)

        # Constant time comparison
        if not hmac.compare_digest(encoded_sig, expected_sig_encoded):
            return None

        payload = json.loads(_base64_url_decode(encoded_payload).decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None  # Token expired

        return payload
    except Exception as err:
        print(f"Token verification error: {err}")
        return None
