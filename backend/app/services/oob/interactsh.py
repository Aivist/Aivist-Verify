# ==============================================================================
# The REAL interactsh transport — speaks the ProjectDiscovery interactsh HTTP API and
# does the RSA/AES decryption of polled interactions.
#
# INFRASTRUCTURE ONLY, not wired to any verdict path (see services/oob/__init__.py).
#
# Protocol (interactsh server, v1):
#   register   POST {server}/register   {"public-key": b64(PEM SPKI), "secret-key": <uuid>,
#                                        "correlation-id": <20-char id>}
#   poll       GET  {server}/poll?id=<correlation-id>&secret=<uuid>
#                    -> {"aes_key": b64(RSA-OAEP-SHA256 enc AES key), "data": [b64(AES-CFB ct), ...]}
#   deregister POST {server}/deregister {"correlation-id": ..., "secret-key": ...}
#
# Each polled `data` item, once decrypted, is a JSON interaction:
#   {"protocol","unique-id","full-id","q-type","raw-request","remote-address","timestamp", ...}
#
# `cryptography` and `httpx` are used here; `cryptography` is lazy-imported so importing
# this module never fails on a machine without it — a clear OOBConfigError is raised only
# when a real transport is actually constructed. This transport CANNOT be exercised without
# a reachable interactsh server, so it has no offline test; the session's correlation logic
# is proven offline via StubTransport instead.
# ==============================================================================
from __future__ import annotations

import base64
import json
from typing import Any, List, Optional

import httpx

from backend.app.services.oob import (
    OOBConfigError,
    OOBInteraction,
    OOBSession,
    OOBTransportError,
    Transport,
    _server_domain,
)

_HTTP_TIMEOUT = 10.0


class InteractshTransport(Transport):
    """A single interactsh client keypair + HTTP session. One transport backs one
    OOBSession (it holds the RSA private key used to decrypt that session's interactions)."""

    def __init__(
        self,
        server_url: str,
        *,
        token: Optional[str] = None,
        http: Optional[httpx.Client] = None,
    ) -> None:
        # Fail fast on a malformed server URL (same parse the session uses for domains).
        _server_domain(server_url)
        self._base = self._normalize_base(server_url)
        self._token = token
        self._http = http or httpx.Client(timeout=_HTTP_TIMEOUT, verify=True)
        self._owns_http = http is None
        self._private_key, self._public_key_b64 = self._generate_keypair()

    # -- key material ----------------------------------------------------------
    @staticmethod
    def _generate_keypair():
        """RSA-2048 keypair; the public key is PEM(SubjectPublicKeyInfo), base64-encoded —
        exactly what the interactsh server expects at /register."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError as e:  # pragma: no cover - environment-dependent
            raise OOBConfigError(
                "the 'cryptography' package is required for the interactsh transport. "
                "Install it with: pip install cryptography"
            ) from e
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_key, base64.b64encode(pub_pem).decode("ascii")

    @staticmethod
    def _normalize_base(server_url: str) -> str:
        raw = (server_url or "").strip().rstrip("/")
        return raw if "://" in raw else "https://" + raw

    def _headers(self) -> dict:
        return {"Authorization": self._token} if self._token else {}

    # -- Transport protocol ----------------------------------------------------
    def register(self, session: OOBSession) -> None:
        body = {
            "public-key": self._public_key_b64,
            "secret-key": session.secret,
            "correlation-id": session.correlation_id,
        }
        try:
            resp = self._http.post(f"{self._base}/register", json=body, headers=self._headers())
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OOBTransportError(f"interactsh register failed: {e}") from e

    def deregister(self, session: OOBSession) -> None:
        body = {"correlation-id": session.correlation_id, "secret-key": session.secret}
        try:
            resp = self._http.post(f"{self._base}/deregister", json=body, headers=self._headers())
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OOBTransportError(f"interactsh deregister failed: {e}") from e
        finally:
            if self._owns_http:
                self._http.close()

    def poll(self, session: OOBSession) -> List[OOBInteraction]:
        params = {"id": session.correlation_id, "secret": session.secret}
        try:
            resp = self._http.get(f"{self._base}/poll", params=params, headers=self._headers())
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as e:
            raise OOBTransportError(f"interactsh poll failed: {e}") from e
        except ValueError as e:
            raise OOBTransportError(f"interactsh poll returned non-JSON: {e}") from e

        data = payload.get("data") or []
        if not data:
            return []
        aes_key = self._decrypt_aes_key(payload.get("aes_key"))
        out: List[OOBInteraction] = []
        for item in data:
            out.append(self._parse_interaction(self._decrypt_item(aes_key, item)))
        return out

    # -- crypto ----------------------------------------------------------------
    def _decrypt_aes_key(self, aes_key_b64: Optional[str]) -> bytes:
        if not aes_key_b64:
            raise OOBTransportError("interactsh poll response carried data but no aes_key")
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            enc = base64.b64decode(aes_key_b64)
            return self._private_key.decrypt(
                enc,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            raise OOBTransportError(f"could not decrypt the interactsh AES key: {e}") from e

    def _decrypt_item(self, aes_key: bytes, item_b64: str) -> dict:
        """AES-CTR: the first 16 bytes are the initial counter block, the rest is the
        ciphertext. The interactsh server encrypts each interaction with AES-256-CTR and
        prepends the IV; verified against the live public interactsh servers (a CFB reading
        decrypts only the first 16-byte block correctly — CFB and CTR share block 0 — then
        diverges, which is exactly the failure this decode avoids)."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            blob = base64.b64decode(item_b64)
            iv, ciphertext = blob[:16], blob[16:]
            decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            raise OOBTransportError(f"could not decrypt an interactsh interaction: {e}") from e

    @staticmethod
    def _parse_interaction(obj: Any) -> OOBInteraction:
        """Map an interactsh interaction JSON object onto our neutral OOBInteraction.
        `unique-id` (falling back to `full-id`) is the 33-char leftmost label correlation
        keys on; it is lowercased to survive DNS 0x20 case randomization."""
        if not isinstance(obj, dict):
            raise OOBTransportError(f"unexpected interactsh interaction shape: {type(obj).__name__}")
        uid = (obj.get("unique-id") or obj.get("full-id") or "").lower()
        return OOBInteraction(
            protocol=str(obj.get("protocol") or "").lower(),
            unique_id=uid,
            remote_address=obj.get("remote-address"),
            timestamp=obj.get("timestamp"),
            q_type=obj.get("q-type"),
            raw_request=obj.get("raw-request"),
        )
