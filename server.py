from __future__ import annotations

import argparse
import secrets
import socket
import threading
import uuid
from pathlib import Path
from typing import Any

from ca import identity_cert_path, identity_private_path, ca_public_path
from crypto_utils import (
    CRYPTO_SUITE,
    PROTOCOL_VERSION,
    ProtocolError,
    ReplayError,
    SecureSession,
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
    public_key_fingerprint,
    read_json,
    recv_json,
    rsa_decrypt,
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
from storage import FileStorage


class SecureZeroServer:
    def __init__(
        self,
        host: str,
        port: int,
        pki_dir: Path,
        data_dir: Path,
        log_dir: Path,
        server_id: str = "server",
    ):
        self.host = host
        self.port = port
        self.server_id = server_id
        self.ca_public_key = load_public_key(ca_public_path(pki_dir))
        self.private_key = load_private_key(identity_private_path(pki_dir, server_id))
        self.certificate = read_json(identity_cert_path(pki_dir, server_id))
        verify_certificate(self.certificate, self.ca_public_key, expected_subject=server_id)
        self.storage = FileStorage(data_dir)
        self.logger = setup_logger("securezero-server", log_dir / "server.log")
        self.seen_request_ids: set[str] = set()
        self.seen_lock = threading.Lock()

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            self.logger.info("server_started host=%s port=%s", self.host, self.port)
            print(f"SecureZero server listening on {self.host}:{self.port}")
            while True:
                conn, addr = server_socket.accept()
                thread = threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True)
                thread.start()

    def handle_connection(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        client_id = "unknown"
        try:
            with conn:
                client_id, client_cert, session = self.perform_handshake(conn, peer)
                self.logger.info("connection_authenticated client=%s peer=%s", client_id, peer)
                while True:
                    message_type, payload = session.recv(conn)
                    if message_type == "BYE":
                        session.send(conn, "RESPONSE", {"ok": True})
                        break
                    response = self.dispatch_request(message_type, payload, client_id, client_cert)
                    session.send(conn, "RESPONSE", response)
        except EOFError:
            self.logger.info("connection_closed client=%s peer=%s", client_id, peer)
        except ReplayError as exc:
            self.logger.warning("replay_detected client=%s peer=%s error=%s", client_id, peer, exc)
        except Exception as exc:
            self.logger.warning("connection_failed client=%s peer=%s error=%s", client_id, peer, exc)

    def perform_handshake(self, conn: socket.socket, peer: str) -> tuple[str, dict[str, Any], SecureSession]:
        client_hello = recv_json(conn)
        if client_hello.get("type") != "CLIENT_HELLO":
            raise ProtocolError("expected CLIENT_HELLO")
        if client_hello.get("version") != PROTOCOL_VERSION or client_hello.get("suite") != CRYPTO_SUITE:
            raise ProtocolError("unsupported protocol version or crypto suite")
        if not is_fresh_timestamp(client_hello["timestamp"]):
            raise ProtocolError("stale client hello timestamp")

        client_cert = client_hello["certificate"]
        client_public_key = verify_certificate(client_cert, self.ca_public_key)
        client_id = client_cert["subject_id"]
        if client_hello.get("client_id") != client_id:
            raise ProtocolError("client hello identity does not match certificate")
        self.logger.info("certificate_verified client=%s peer=%s", client_id, peer)

        server_nonce = secrets.token_bytes(32)
        server_hello = {
            "type": "SERVER_HELLO",
            "version": PROTOCOL_VERSION,
            "suite": CRYPTO_SUITE,
            "server_id": self.server_id,
            "certificate": self.certificate,
            "nonce": b64e(server_nonce),
            "timestamp": utc_now_iso(),
        }
        send_json(conn, server_hello)

        key_exchange = recv_json(conn)
        if key_exchange.get("type") != "CLIENT_KEY_EXCHANGE":
            raise ProtocolError("expected CLIENT_KEY_EXCHANGE")
        if not is_fresh_timestamp(key_exchange["timestamp"]):
            raise ProtocolError("stale key exchange timestamp")

        encrypted_premaster_b64 = key_exchange["encrypted_premaster"]
        transcript = handshake_transcript(client_hello, server_hello, encrypted_premaster_b64)
        if not rsa_verify(client_public_key, b64d(key_exchange["signature"]), transcript):
            self.logger.warning("client_signature_failed client=%s peer=%s", client_id, peer)
            raise ProtocolError("client proof-of-possession failed")

        premaster = rsa_decrypt(self.private_key, b64d(encrypted_premaster_b64))
        client_nonce = b64d(client_hello["nonce"])
        c2s_key, s2c_key, session_id = derive_session_keys(premaster, client_nonce, server_nonce)
        session = SecureSession("server", session_id, c2s_key, s2c_key)

        server_signature = rsa_sign(self.private_key, server_finished_data(transcript, session_id))
        session.send(
            conn,
            "SERVER_FINISHED",
            {
                "server_id": self.server_id,
                "signature": b64e(server_signature),
                "certificate_fingerprint": certificate_fingerprint(self.certificate),
            },
        )

        finished_type, finished_payload = session.recv(conn)
        if finished_type != "CLIENT_FINISHED":
            raise ProtocolError("expected CLIENT_FINISHED")
        if not rsa_verify(
            client_public_key,
            b64d(finished_payload["signature"]),
            client_finished_data(transcript, session_id),
        ):
            self.logger.warning("client_finished_signature_failed client=%s peer=%s", client_id, peer)
            raise ProtocolError("client finished signature failed")

        self.logger.info("handshake_complete client=%s session=%s", client_id, session_id)
        return client_id, client_cert, session

    def dispatch_request(
        self, message_type: str, payload: dict[str, Any], client_id: str, client_cert: dict[str, Any]
    ) -> dict[str, Any]:
        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            return {"ok": False, "error": "missing request_id"}
        if not self.remember_request_id(request_id):
            self.logger.warning("request_replay_rejected client=%s request_id=%s", client_id, request_id)
            return {"ok": False, "error": "replayed request_id"}

        try:
            if message_type == "UPLOAD":
                return self.handle_upload(payload, client_id, client_cert)
            if message_type == "LIST":
                return self.handle_list(client_id)
            if message_type == "DOWNLOAD":
                return self.handle_download(payload, client_id)
            return {"ok": False, "error": f"unknown message type {message_type}"}
        except Exception as exc:
            self.logger.warning("request_failed client=%s type=%s error=%s", client_id, message_type, exc)
            return {"ok": False, "error": str(exc)}

    def remember_request_id(self, request_id: str) -> bool:
        with self.seen_lock:
            if request_id in self.seen_request_ids:
                return False
            self.seen_request_ids.add(request_id)
            return True

    def handle_upload(
        self, payload: dict[str, Any], client_id: str, handshake_cert: dict[str, Any]
    ) -> dict[str, Any]:
        package = payload.get("package")
        if not isinstance(package, dict):
            raise ProtocolError("upload package must be an object")
        self.validate_upload_package(package, client_id, handshake_cert)
        self.storage.store_package(package)
        self.logger.info(
            "file_uploaded file_id=%s sender=%s recipient=%s expires=%s",
            package["file_id"],
            package["sender_id"],
            package["recipient_id"],
            package["expiration_time"],
        )
        return {"ok": True, "file_id": package["file_id"]}

    def validate_upload_package(
        self, package: dict[str, Any], client_id: str, handshake_cert: dict[str, Any]
    ) -> None:
        try:
            parsed_file_id = uuid.UUID(package["file_id"])
        except (KeyError, ValueError, TypeError) as exc:
            raise ProtocolError("file_id must be a UUID") from exc
        if str(parsed_file_id) != package["file_id"]:
            raise ProtocolError("file_id must use canonical UUID formatting")
        filename = package.get("filename")
        if not isinstance(filename, str) or not filename or "/" in filename or "\\" in filename:
            raise ProtocolError("filename must be a simple file name")
        if package.get("sender_id") != client_id:
            raise ProtocolError("authenticated sender does not match package sender")
        if certificate_fingerprint(package["sender_certificate"]) != certificate_fingerprint(handshake_cert):
            raise ProtocolError("package sender certificate does not match handshake certificate")
        sender_public = verify_certificate(
            package["sender_certificate"], self.ca_public_key, expected_subject=package["sender_id"]
        )
        verify_certificate(
            package["recipient_certificate"], self.ca_public_key, expected_subject=package["recipient_id"]
        )
        if public_key_fingerprint(sender_public) != public_key_fingerprint(
            verify_certificate(handshake_cert, self.ca_public_key, expected_subject=client_id)
        ):
            raise ProtocolError("sender public key mismatch")
        if parse_utc_iso(package["expiration_time"]) <= utc_now():
            raise ProtocolError("file is already expired")
        ciphertext = b64d(package["encrypted_file"])
        if sha256_hex(ciphertext) != package["ciphertext_sha256"]:
            raise ProtocolError("ciphertext hash mismatch")
        if not rsa_verify(sender_public, b64d(package["signature"]), file_signature_payload(package)):
            self.logger.warning("upload_signature_failed sender=%s file_id=%s", client_id, package.get("file_id"))
            raise ProtocolError("file package signature verification failed")

    def handle_list(self, client_id: str) -> dict[str, Any]:
        rows = self.storage.list_for_user(client_id)
        visible_rows = []
        for row in rows:
            if parse_utc_iso(row["expiration_time"]) <= utc_now():
                visible = dict(row)
                visible["status"] = "expired"
            else:
                visible = dict(row)
            visible_rows.append(visible)
        self.logger.info("files_listed client=%s count=%s", client_id, len(visible_rows))
        return {"ok": True, "files": visible_rows}

    def handle_download(self, payload: dict[str, Any], client_id: str) -> dict[str, Any]:
        file_id = payload.get("file_id")
        if not isinstance(file_id, str):
            raise ProtocolError("file_id is required")
        metadata = self.storage.get_metadata(file_id)
        if metadata is None:
            self.logger.warning("download_missing client=%s file_id=%s", client_id, file_id)
            return {"ok": False, "error": "file not found"}
        if metadata["recipient_id"] != client_id:
            self.logger.warning(
                "download_unauthorized client=%s file_id=%s owner=%s",
                client_id,
                file_id,
                metadata["recipient_id"],
            )
            return {"ok": False, "error": "not authorized to download this file"}
        if parse_utc_iso(metadata["expiration_time"]) <= utc_now():
            self.storage.update_metadata(file_id, {"status": "expired"})
            self.logger.warning("download_expired client=%s file_id=%s", client_id, file_id)
            return {"ok": False, "error": "file is expired"}
        package = self.storage.load_package(file_id)
        self.storage.update_metadata(
            file_id,
            {
                "status": "stored",
                "download_count": metadata.get("download_count", 0) + 1,
                "last_download_time": utc_now_iso(),
            },
        )
        self.logger.info("file_downloaded client=%s file_id=%s", client_id, file_id)
        return {"ok": True, "package": package, "metadata": metadata}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureZero file-drop server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--pki-dir", default="pki")
    parser.add_argument("--data-dir", default="server_data")
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("--server-id", default="server")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    server = SecureZeroServer(
        host=args.host,
        port=args.port,
        pki_dir=Path(args.pki_dir),
        data_dir=Path(args.data_dir),
        log_dir=Path(args.log_dir),
        server_id=args.server_id,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
