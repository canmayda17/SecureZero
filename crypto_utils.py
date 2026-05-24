from __future__ import annotations

import base64
import json
import logging
import secrets
import socket
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ModuleNotFoundError as exc:  # pragma: no cover - helpful runtime message
    raise SystemExit(
        "Missing dependency: cryptography. Install it with: pip install -r requirements.txt"
    ) from exc


PROTOCOL_VERSION = "SZFD/1"
CRYPTO_SUITE = "RSA-OAEP-HKDF-AESGCM-RSAPSS"
CA_ISSUER = "SecureZero CA"
MAX_FRAME_SIZE = 32 * 1024 * 1024
HELLO_MAX_SKEW_SECONDS = 300


class ProtocolError(Exception):
    pass


class ReplayError(ProtocolError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_utc_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_fresh_timestamp(value: str, max_skew_seconds: int = HELLO_MAX_SKEW_SECONDS) -> bool:
    timestamp = parse_utc_iso(value)
    return abs(utc_now() - timestamp) <= timedelta(seconds=max_skew_seconds)


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def sha256_hex(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_private_key(private_key: rsa.RSAPrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(data)


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def save_public_key(public_key: rsa.RSAPublicKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(public_key_pem(public_key).encode("utf-8"))


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def public_key_from_pem(pem: str) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    return sha256_hex(public_key_pem(public_key).encode("utf-8"))


def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def rsa_verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def certificate_tbs(certificate: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in certificate.items() if key != "signature"}


def verify_certificate(
    certificate: dict[str, Any],
    ca_public_key: rsa.RSAPublicKey,
    expected_subject: str | None = None,
) -> rsa.RSAPublicKey:
    required = {
        "subject_id",
        "public_key_pem",
        "issuer",
        "serial",
        "not_before",
        "not_after",
        "signature",
    }
    missing = sorted(required - set(certificate))
    if missing:
        raise ProtocolError(f"certificate is missing fields: {', '.join(missing)}")

    if expected_subject is not None and certificate["subject_id"] != expected_subject:
        raise ProtocolError("certificate subject does not match expected identity")
    if certificate["issuer"] != CA_ISSUER:
        raise ProtocolError("certificate issuer is not trusted")

    now = utc_now()
    if parse_utc_iso(certificate["not_before"]) > now:
        raise ProtocolError("certificate is not valid yet")
    if parse_utc_iso(certificate["not_after"]) < now:
        raise ProtocolError("certificate is expired")

    if not rsa_verify(ca_public_key, b64d(certificate["signature"]), canonical_json(certificate_tbs(certificate))):
        raise ProtocolError("certificate signature verification failed")

    return public_key_from_pem(certificate["public_key_pem"])


def certificate_fingerprint(certificate: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(certificate_tbs(certificate)))


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def derive_session_keys(
    premaster_secret: bytes, client_nonce: bytes, server_nonce: bytes
) -> tuple[bytes, bytes, str]:
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=client_nonce + server_nonce,
        info=b"SecureZero FileDrop v1 session keys",
    ).derive(premaster_secret)
    client_to_server_key = material[:32]
    server_to_client_key = material[32:64]
    session_id = sha256_hex(material[64:] + client_nonce + server_nonce)[:32]
    return client_to_server_key, server_to_client_key, session_id


def send_json(sock: socket.socket, message: dict[str, Any]) -> None:
    encoded = canonical_json(message)
    if len(encoded) > MAX_FRAME_SIZE:
        raise ProtocolError("frame too large")
    sock.sendall(struct.pack("!I", len(encoded)) + encoded)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_json(sock: socket.socket) -> dict[str, Any]:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > MAX_FRAME_SIZE:
        raise ProtocolError("invalid frame length")
    decoded = json.loads(recv_exact(sock, length).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ProtocolError("frame must contain a JSON object")
    return decoded


class SecureSession:
    def __init__(self, role: str, session_id: str, client_to_server_key: bytes, server_to_client_key: bytes):
        if role not in {"client", "server"}:
            raise ValueError("role must be client or server")
        self.role = role
        self.session_id = session_id
        self.client_to_server_key = client_to_server_key
        self.server_to_client_key = server_to_client_key
        self.send_seq = 0
        self.recv_seq = 0

    def _send_key(self) -> bytes:
        return self.client_to_server_key if self.role == "client" else self.server_to_client_key

    def _recv_key(self) -> bytes:
        return self.server_to_client_key if self.role == "client" else self.client_to_server_key

    def send(self, sock: socket.socket, message_type: str, payload: dict[str, Any]) -> None:
        seq = self.send_seq
        self.send_seq += 1
        aad_object = {"session_id": self.session_id, "seq": seq, "type": message_type}
        plaintext = canonical_json({"type": message_type, "payload": payload})
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._send_key()).encrypt(nonce, plaintext, canonical_json(aad_object))
        send_json(
            sock,
            {
                "secure": True,
                "session_id": self.session_id,
                "seq": seq,
                "type": message_type,
                "nonce": b64e(nonce),
                "ciphertext": b64e(ciphertext),
            },
        )

    def recv(self, sock: socket.socket) -> tuple[str, dict[str, Any]]:
        envelope = recv_json(sock)
        if envelope.get("secure") is not True:
            raise ProtocolError("expected secure frame")
        if envelope.get("session_id") != self.session_id:
            raise ProtocolError("session id mismatch")
        seq = envelope.get("seq")
        if seq != self.recv_seq:
            raise ReplayError("unexpected or replayed sequence number")
        message_type = envelope.get("type")
        if not isinstance(message_type, str):
            raise ProtocolError("secure frame has invalid type")

        aad_object = {"session_id": self.session_id, "seq": seq, "type": message_type}
        plaintext = AESGCM(self._recv_key()).decrypt(
            b64d(envelope["nonce"]),
            b64d(envelope["ciphertext"]),
            canonical_json(aad_object),
        )
        decoded = json.loads(plaintext.decode("utf-8"))
        if decoded.get("type") != message_type or not isinstance(decoded.get("payload"), dict):
            raise ProtocolError("secure plaintext type mismatch")
        self.recv_seq += 1
        return message_type, decoded["payload"]


def handshake_transcript(
    client_hello: dict[str, Any], server_hello: dict[str, Any], encrypted_premaster_b64: str
) -> bytes:
    return canonical_json(
        {
            "client_hello": client_hello,
            "server_hello": server_hello,
            "encrypted_premaster": encrypted_premaster_b64,
        }
    )


def server_finished_data(transcript: bytes, session_id: str) -> bytes:
    return canonical_json(
        {
            "label": "server finished",
            "session_id": session_id,
            "transcript_hash": sha256_hex(transcript),
        }
    )


def client_finished_data(transcript: bytes, session_id: str) -> bytes:
    return canonical_json(
        {
            "label": "client finished",
            "session_id": session_id,
            "transcript_hash": sha256_hex(transcript),
        }
    )


SIGNED_PACKAGE_FIELDS = [
    "file_id",
    "sender_id",
    "recipient_id",
    "filename",
    "upload_time",
    "expiration_time",
    "file_nonce",
    "file_aad",
    "wrapped_key",
    "plaintext_sha256",
    "ciphertext_sha256",
    "sender_certificate",
    "recipient_certificate",
]


def file_signature_payload(package: dict[str, Any]) -> bytes:
    missing = [field for field in SIGNED_PACKAGE_FIELDS if field not in package]
    if missing:
        raise ProtocolError(f"file package is missing signed fields: {', '.join(missing)}")
    return canonical_json({field: package[field] for field in SIGNED_PACKAGE_FIELDS})


def setup_logger(name: str, path: Path) -> logging.Logger:
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    return logger
