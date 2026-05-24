from __future__ import annotations

import argparse
import secrets
from datetime import timedelta
from pathlib import Path

from crypto_utils import (
    CA_ISSUER,
    b64e,
    canonical_json,
    generate_private_key,
    load_private_key,
    load_public_key,
    public_key_pem,
    rsa_sign,
    save_private_key,
    save_public_key,
    utc_now,
    verify_certificate,
    write_json,
    read_json,
)


DEFAULT_PKI_DIR = Path("pki")


def ca_private_path(pki_dir: Path) -> Path:
    return pki_dir / "ca_private.pem"


def ca_public_path(pki_dir: Path) -> Path:
    return pki_dir / "ca_public.pem"


def identity_private_path(pki_dir: Path, identity: str) -> Path:
    return pki_dir / f"{identity}_private.pem"


def identity_cert_path(pki_dir: Path, identity: str) -> Path:
    return pki_dir / f"{identity}_cert.json"


def build_certificate(identity: str, public_key: str, ca_private_key, days: int) -> dict:
    now = utc_now()
    certificate = {
        "subject_id": identity,
        "public_key_pem": public_key,
        "issuer": CA_ISSUER,
        "serial": secrets.token_hex(16),
        "not_before": (now - timedelta(minutes=1)).isoformat(timespec="seconds"),
        "not_after": (now + timedelta(days=days)).isoformat(timespec="seconds"),
    }
    certificate["signature"] = b64e(rsa_sign(ca_private_key, canonical_json(certificate)))
    return certificate


def cmd_init(args: argparse.Namespace) -> None:
    pki_dir = Path(args.pki_dir)
    private_path = ca_private_path(pki_dir)
    public_path = ca_public_path(pki_dir)
    if private_path.exists() and not args.overwrite:
        raise SystemExit(f"CA already exists at {private_path}. Use --overwrite to replace it.")
    key = generate_private_key()
    save_private_key(key, private_path)
    save_public_key(key.public_key(), public_path)
    print(f"Created CA key pair in {pki_dir}")


def issue_identity(pki_dir: Path, identity: str, days: int, overwrite: bool = False) -> None:
    ca_key = load_private_key(ca_private_path(pki_dir))
    private_path = identity_private_path(pki_dir, identity)
    cert_path = identity_cert_path(pki_dir, identity)
    if (private_path.exists() or cert_path.exists()) and not overwrite:
        raise SystemExit(f"{identity} already has key/certificate. Use --overwrite to replace it.")
    private_key = generate_private_key()
    certificate = build_certificate(identity, public_key_pem(private_key.public_key()), ca_key, days)
    save_private_key(private_key, private_path)
    write_json(cert_path, certificate)
    print(f"Issued certificate for {identity}: {cert_path}")


def cmd_issue(args: argparse.Namespace) -> None:
    issue_identity(Path(args.pki_dir), args.id, args.days, args.overwrite)


def cmd_demo(args: argparse.Namespace) -> None:
    pki_dir = Path(args.pki_dir)
    if not ca_private_path(pki_dir).exists() or args.overwrite:
        cmd_init(argparse.Namespace(pki_dir=pki_dir, overwrite=args.overwrite))
    for identity in ["server", "alice", "bob", "mallory"]:
        issue_identity(pki_dir, identity, args.days, args.overwrite)
    print("Demo PKI ready: server, alice, bob, mallory")


def cmd_verify(args: argparse.Namespace) -> None:
    pki_dir = Path(args.pki_dir)
    ca_public = load_public_key(ca_public_path(pki_dir))
    certificate = read_json(identity_cert_path(pki_dir, args.id))
    verify_certificate(certificate, ca_public, expected_subject=args.id)
    print(f"Certificate for {args.id} is valid.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureZero simple Certificate Authority")
    parser.add_argument("--pki-dir", default=str(DEFAULT_PKI_DIR), help="PKI directory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create CA key pair")
    init_parser.add_argument("--overwrite", action="store_true")
    init_parser.set_defaults(func=cmd_init)

    issue_parser = subparsers.add_parser("issue", help="issue one identity certificate")
    issue_parser.add_argument("--id", required=True, help="identity, for example alice or server")
    issue_parser.add_argument("--days", type=int, default=365)
    issue_parser.add_argument("--overwrite", action="store_true")
    issue_parser.set_defaults(func=cmd_issue)

    demo_parser = subparsers.add_parser("demo", help="create demo certificates")
    demo_parser.add_argument("--days", type=int, default=365)
    demo_parser.add_argument("--overwrite", action="store_true")
    demo_parser.set_defaults(func=cmd_demo)

    verify_parser = subparsers.add_parser("verify", help="verify one issued certificate")
    verify_parser.add_argument("--id", required=True)
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
