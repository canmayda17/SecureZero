from __future__ import annotations

import argparse
import json
import secrets
import socket
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

from ca import ca_public_path, identity_cert_path, identity_private_path
from crypto_utils import (
    CRYPTO_SUITE,
    PROTOCOL_VERSION,
    ProtocolError,
    SecureSession,
    aesgcm_decrypt,
    b64d,
    b64e,
    certificate_fingerprint,
    client_finished_data,
    derive_session_keys,
    file_signature_payload,
    handshake_transcript,
    is_fresh_timestamp,
    load_private_key,
    load_public_key,
    parse_utc_iso,
    read_json,
    recv_json,
    rsa_decrypt,
    rsa_encrypt,
    rsa_sign,
    rsa_verify,
    send_json,
    server_finished_data,
    setup_logger,
    sha256_hex,
    utc_now,
    utc_now_iso,
    verify_certificate,
)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: cryptography. Install it with: pip install -r requirements.txt"
    ) from exc


class SecureZeroClient:
    def __init__(
        self,
        identity: str,
        host: str,
        port: int,
        pki_dir: Path,
        log_dir: Path,
        server_id: str = "server",
    ):
        self.identity = identity
        self.host = host
        self.port = port
        self.server_id = server_id
        self.pki_dir = pki_dir
        self.ca_public_key = load_public_key(ca_public_path(pki_dir))
        self.private_key = load_private_key(identity_private_path(pki_dir, identity))
        self.certificate = read_json(identity_cert_path(pki_dir, identity))
        verify_certificate(self.certificate, self.ca_public_key, expected_subject=identity)
        self.logger = setup_logger(f"securezero-client-{identity}", log_dir / f"client_{identity}.log")

    def connect(self) -> tuple[socket.socket, SecureSession]:
        sock = socket.create_connection((self.host, self.port), timeout=10)
        try:
            session = self.perform_handshake(sock)
            self.logger.info("connected identity=%s server=%s:%s", self.identity, self.host, self.port)
            return sock, session
        except Exception:
            sock.close()
            raise

    def perform_handshake(self, sock: socket.socket) -> SecureSession:
        client_nonce = secrets.token_bytes(32)
        client_hello = {
            "type": "CLIENT_HELLO",
            "version": PROTOCOL_VERSION,
            "suite": CRYPTO_SUITE,
            "client_id": self.identity,
            "certificate": self.certificate,
            "nonce": b64e(client_nonce),
            "timestamp": utc_now_iso(),
        }
        send_json(sock, client_hello)

        server_hello = recv_json(sock)
        if server_hello.get("type") != "SERVER_HELLO":
            raise ProtocolError("expected SERVER_HELLO")
        if server_hello.get("version") != PROTOCOL_VERSION or server_hello.get("suite") != CRYPTO_SUITE:
            raise ProtocolError("server selected unsupported protocol or crypto suite")
        if server_hello.get("server_id") != self.server_id:
            raise ProtocolError("unexpected server identity")
        if not is_fresh_timestamp(server_hello["timestamp"]):
            raise ProtocolError("stale server hello timestamp")
        server_public_key = verify_certificate(
            server_hello["certificate"], self.ca_public_key, expected_subject=self.server_id
        )
        self.logger.info("server_certificate_verified server=%s", self.server_id)

        premaster = secrets.token_bytes(32)
        encrypted_premaster = rsa_encrypt(server_public_key, premaster)
        encrypted_premaster_b64 = b64e(encrypted_premaster)
        transcript = handshake_transcript(client_hello, server_hello, encrypted_premaster_b64)
        send_json(
            sock,
            {
                "type": "CLIENT_KEY_EXCHANGE",
                "encrypted_premaster": encrypted_premaster_b64,
                "signature": b64e(rsa_sign(self.private_key, transcript)),
                "timestamp": utc_now_iso(),
            },
        )

        c2s_key, s2c_key, session_id = derive_session_keys(
            premaster, client_nonce, b64d(server_hello["nonce"])
        )
        session = SecureSession("client", session_id, c2s_key, s2c_key)

        finished_type, finished_payload = session.recv(sock)
        if finished_type != "SERVER_FINISHED":
            raise ProtocolError("expected SERVER_FINISHED")
        if finished_payload.get("certificate_fingerprint") != certificate_fingerprint(server_hello["certificate"]):
            raise ProtocolError("server finished certificate fingerprint mismatch")
        if not rsa_verify(
            server_public_key,
            b64d(finished_payload["signature"]),
            server_finished_data(transcript, session_id),
        ):
            raise ProtocolError("server proof-of-possession failed")

        session.send(
            sock,
            "CLIENT_FINISHED",
            {
                "client_id": self.identity,
                "signature": b64e(rsa_sign(self.private_key, client_finished_data(transcript, session_id))),
            },
        )
        self.logger.info("handshake_complete session=%s", session_id)
        return session

    def send_one_request(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        sock, session = self.connect()
        try:
            session.send(sock, message_type, payload)
            response_type, response = session.recv(sock)
            if response_type != "RESPONSE":
                raise ProtocolError(f"unexpected response type: {response_type}")
            session.send(sock, "BYE", {"request_id": str(uuid.uuid4())})
            try:
                session.recv(sock)
            except Exception:
                pass
            return response
        finally:
            sock.close()

    def upload(self, recipient_id: str, file_path: Path, expires_in: int) -> dict[str, Any]:
        recipient_certificate = read_json(identity_cert_path(self.pki_dir, recipient_id))
        recipient_public_key = verify_certificate(
            recipient_certificate, self.ca_public_key, expected_subject=recipient_id
        )
        plaintext = file_path.read_bytes()
        file_key = AESGCM.generate_key(bit_length=256)
        file_id = str(uuid.uuid4())
        file_aad = {
            "file_id": file_id,
            "sender_id": self.identity,
            "recipient_id": recipient_id,
        }
        aad_bytes = json.dumps(file_aad, sort_keys=True, separators=(",", ":")).encode("utf-8")
        file_nonce = secrets.token_bytes(12)
        encrypted_file = AESGCM(file_key).encrypt(file_nonce, plaintext, aad_bytes)
        wrapped_key = rsa_encrypt(recipient_public_key, file_key)
        package = {
            "file_id": file_id,
            "sender_id": self.identity,
            "recipient_id": recipient_id,
            "filename": file_path.name,
            "upload_time": utc_now_iso(),
            "expiration_time": (utc_now() + timedelta(seconds=expires_in)).isoformat(timespec="seconds"),
            "file_nonce": b64e(file_nonce),
            "file_aad": b64e(aad_bytes),
            "wrapped_key": b64e(wrapped_key),
            "plaintext_sha256": sha256_hex(plaintext),
            "ciphertext_sha256": sha256_hex(encrypted_file),
            "encrypted_file": b64e(encrypted_file),
            "sender_certificate": self.certificate,
            "recipient_certificate": recipient_certificate,
        }
        package["signature"] = b64e(rsa_sign(self.private_key, file_signature_payload(package)))
        response = self.send_one_request(
            "UPLOAD", {"request_id": str(uuid.uuid4()), "package": package}
        )
        if response.get("ok"):
            self.logger.info("upload_ok file_id=%s recipient=%s", file_id, recipient_id)
        else:
            self.logger.warning("upload_failed recipient=%s error=%s", recipient_id, response.get("error"))
        return response

    def list_files(self) -> dict[str, Any]:
        response = self.send_one_request("LIST", {"request_id": str(uuid.uuid4())})
        if response.get("ok"):
            self.logger.info("list_ok count=%s", len(response.get("files", [])))
        else:
            self.logger.warning("list_failed error=%s", response.get("error"))
        return response

    def download(self, file_id: str, out_path: Path) -> dict[str, Any]:
        response = self.send_one_request(
            "DOWNLOAD", {"request_id": str(uuid.uuid4()), "file_id": file_id}
        )
        if not response.get("ok"):
            self.logger.warning("download_failed file_id=%s error=%s", file_id, response.get("error"))
            return response

        package = response["package"]
        sender_public_key = verify_certificate(
            package["sender_certificate"], self.ca_public_key, expected_subject=package["sender_id"]
        )
        verify_certificate(
            package["recipient_certificate"], self.ca_public_key, expected_subject=self.identity
        )
        if package["recipient_id"] != self.identity:
            raise ProtocolError("downloaded package is not addressed to this client")
        if parse_utc_iso(package["expiration_time"]) <= utc_now():
            raise ProtocolError("downloaded package is expired")
        if sha256_hex(b64d(package["encrypted_file"])) != package["ciphertext_sha256"]:
            raise ProtocolError("downloaded ciphertext hash mismatch")
        if not rsa_verify(sender_public_key, b64d(package["signature"]), file_signature_payload(package)):
            raise ProtocolError("sender signature verification failed")

        file_key = rsa_decrypt(self.private_key, b64d(package["wrapped_key"]))
        plaintext = aesgcm_decrypt(
            file_key,
            b64d(package["file_nonce"]),
            b64d(package["encrypted_file"]),
            b64d(package["file_aad"]),
        )
        if sha256_hex(plaintext) != package["plaintext_sha256"]:
            raise ProtocolError("plaintext hash mismatch after decrypt")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(plaintext)
        self.logger.info("download_ok file_id=%s out=%s", file_id, out_path)
        return {"ok": True, "file_id": file_id, "out": str(out_path), "sender_id": package["sender_id"]}


def print_response(response: dict[str, Any]) -> None:
    print(json.dumps(response, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureZero file-drop client")
    parser.add_argument("--id", required=True, help="client identity")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--pki-dir", default="pki")
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("--server-id", default="server")
    subparsers = parser.add_subparsers(dest="command", required=True)

    upload_parser = subparsers.add_parser("upload", help="upload encrypted file")
    upload_parser.add_argument("--to", required=True, help="recipient identity")
    upload_parser.add_argument("--file", required=True, type=Path)
    upload_parser.add_argument("--expires-in", type=int, default=3600, help="expiration in seconds")

    subparsers.add_parser("list", help="list files visible to this identity")

    download_parser = subparsers.add_parser("download", help="download and decrypt a file")
    download_parser.add_argument("--file-id", required=True)
    download_parser.add_argument("--out", required=True, type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    client = SecureZeroClient(
        identity=args.id,
        host=args.host,
        port=args.port,
        pki_dir=Path(args.pki_dir),
        log_dir=Path(args.log_dir),
        server_id=args.server_id,
    )
    if args.command == "upload":
        print_response(client.upload(args.to, args.file, args.expires_in))
    elif args.command == "list":
        print_response(client.list_files())
    elif args.command == "download":
        print_response(client.download(args.file_id, args.out))
    else:
        raise SystemExit(f"unknown command {args.command}")


if __name__ == "__main__":
    main()
