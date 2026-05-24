from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from crypto_utils import read_json, write_json


class FileStorage:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.files_dir = base_dir / "files"
        self.metadata_path = base_dir / "metadata.json"
        self.lock = threading.Lock()
        self.files_dir.mkdir(parents=True, exist_ok=True)
        if not self.metadata_path.exists():
            write_json(self.metadata_path, {})

    def _load_metadata(self) -> dict[str, dict[str, Any]]:
        return read_json(self.metadata_path)

    def _save_metadata(self, metadata: dict[str, dict[str, Any]]) -> None:
        write_json(self.metadata_path, metadata)

    def store_package(self, package: dict[str, Any]) -> None:
        file_id = package["file_id"]
        with self.lock:
            metadata = self._load_metadata()
            if file_id in metadata:
                raise ValueError("file id already exists")
            package_path = self.files_dir / f"{file_id}.json"
            write_json(package_path, package)
            metadata[file_id] = {
                "file_id": file_id,
                "sender_id": package["sender_id"],
                "recipient_id": package["recipient_id"],
                "filename": package["filename"],
                "upload_time": package["upload_time"],
                "expiration_time": package["expiration_time"],
                "status": "stored",
                "download_count": 0,
                "last_download_time": None,
            }
            self._save_metadata(metadata)

    def list_for_user(self, user_id: str) -> list[dict[str, Any]]:
        with self.lock:
            metadata = self._load_metadata()
            rows = [
                row
                for row in metadata.values()
                if row["sender_id"] == user_id or row["recipient_id"] == user_id
            ]
        return sorted(rows, key=lambda row: row["upload_time"])

    def get_metadata(self, file_id: str) -> dict[str, Any] | None:
        with self.lock:
            return self._load_metadata().get(file_id)

    def update_metadata(self, file_id: str, updates: dict[str, Any]) -> None:
        with self.lock:
            metadata = self._load_metadata()
            if file_id not in metadata:
                raise KeyError(file_id)
            metadata[file_id].update(updates)
            self._save_metadata(metadata)

    def load_package(self, file_id: str) -> dict[str, Any]:
        return read_json(self.files_dir / f"{file_id}.json")
