"""Sample Vault Storage & Cryptography Engine for M1 Ingestion.

Contract rules:
- Max 100 MiB (104,857,600 bytes) cap.
- `stored_defanged`: true (payload is defanged to prevent execution or host AV triggers).
- `stored_encrypted`: true (payload is encrypted at rest using AES / Fernet).
- Duplicate SHA-256 detection returns existing record with `duplicate_of: <vault_id>`.
- Samples are referenced by `vault_id` UUID, never by local filesystem path.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import uuid

from cryptography.fernet import Fernet

from m1_ingestion.classifier import classify_file
from m1_ingestion.sanitizer import sanitize_filename
from m1_ingestion.scanner import scan_sample

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MiB
DEFANG_XOR_KEY = 0x5A


class SampleVault:
    """Secure encrypted & defanged sample vault."""

    def __init__(self, storage_dir: Optional[Path] = None, encryption_key: Optional[bytes] = None):
        default_dir = Path(__file__).resolve().parent / "data" / "vault"
        self.storage_dir = storage_dir or Path(os.getenv("VAULT_STORAGE_PATH", str(default_dir)))
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = self.storage_dir / "vault_registry.json"

        # Deterministic or configured vault encryption key
        if encryption_key:
            self._key = encryption_key
        else:
            env_key = os.getenv("VAULT_ENCRYPTION_KEY")
            if env_key:
                self._key = env_key.encode() if isinstance(env_key, str) else env_key
            else:
                key_path = self.storage_dir / "vault.key"
                if key_path.exists():
                    self._key = key_path.read_bytes().strip()
                else:
                    self._key = Fernet.generate_key()
                    key_path.write_bytes(self._key)

        self._cipher = Fernet(self._key)
        self._registry: Dict[str, Dict[str, Any]] = self._load_registry()

    def _load_registry(self) -> Dict[str, Dict[str, Any]]:
        if self.registry_file.exists():
            try:
                with open(self.registry_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_registry(self) -> None:
        try:
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(self._registry, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def _defang(data: bytes) -> bytes:
        """XOR defang bytes so they cannot be executed or trigger host AV."""
        return bytes(b ^ DEFANG_XOR_KEY for b in data)

    @staticmethod
    def _refang(data: bytes) -> bytes:
        """Refang (restore original bytes) via inverse XOR."""
        return bytes(b ^ DEFANG_XOR_KEY for b in data)

    def ingest(
        self,
        data: bytes,
        original_name: str,
        submitter: str = "analyst1",
        vault_id: Optional[str] = None,
        analysis_id: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], bool]:
        """Ingest raw sample bytes into vault.

        Returns:
            (sample_record, event_record, is_duplicate)
        """
        size = len(data)
        if size == 0:
            raise ValueError("Sample cannot be empty (size must be at least 1 byte)")
        if size > MAX_FILE_SIZE:
            raise ValueError(f"Sample size {size} exceeds maximum allowed cap of 100 MiB (104857600 bytes)")

        # Calculate standard hashes
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()

        # Sanitize filename and classify
        clean_name = sanitize_filename(original_name)
        file_type, mime_type = classify_file(data, clean_name)
        clamav_result = scan_sample(data)

        # Check deduplication index by SHA-256
        is_duplicate = False
        duplicate_of: Optional[str] = None

        if sha256 in self._registry:
            existing = self._registry[sha256]
            is_duplicate = True
            duplicate_of = existing["vault_id"]
            assigned_vault_id = duplicate_of
        else:
            assigned_vault_id = vault_id or str(uuid.uuid4())

        assigned_analysis_id = analysis_id or str(uuid.uuid4())

        # If new sample, encrypt and store defanged bytes
        if not is_duplicate:
            defanged_bytes = self._defang(data)
            encrypted_payload = self._cipher.encrypt(defanged_bytes)
            sample_file = self.storage_dir / f"{assigned_vault_id}.vault"
            sample_file.write_bytes(encrypted_payload)

            self._registry[sha256] = {
                "vault_id": assigned_vault_id,
                "sha256": sha256,
                "md5": md5,
                "sha1": sha1,
                "size_bytes": size,
                "file_type": file_type,
                "original_name": clean_name,
                "received_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save_registry()

        sample_record: Dict[str, Any] = {
            "vault_id": assigned_vault_id,
            "sha256": sha256,
            "md5": md5,
            "size_bytes": size,
            "file_type": file_type,
            "original_name": clean_name,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "stored_defanged": True,
            "stored_encrypted": True,
        }

        if sha1:
            sample_record["sha1"] = sha1
        if mime_type:
            sample_record["mime"] = mime_type
        if submitter:
            sample_record["submitter"] = submitter
        if clamav_result:
            sample_record["clamav_result"] = clamav_result
        if is_duplicate and duplicate_of:
            sample_record["duplicate_of"] = duplicate_of

        # Payload strictly adhering to events.schema.json
        event_payload: Dict[str, Any] = {
            "sha256": sha256,
            "file_type": file_type,
        }
        if is_duplicate:
            event_payload["duplicate"] = True

        event_record: Dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "type": "sample.received",
            "analysis_id": assigned_analysis_id,
            "vault_id": assigned_vault_id,
            "emitted_at": datetime.now(timezone.utc).isoformat(),
            "producer": "M1",
            "contract_version": "1.0.0",
            "payload": event_payload,
        }

        return sample_record, event_record, is_duplicate

    def retrieve(self, vault_id: str) -> bytes:
        """Retrieve and decrypt original sample bytes by vault_id."""
        sample_file = self.storage_dir / f"{vault_id}.vault"
        if not sample_file.exists():
            raise FileNotFoundError(f"Vault sample {vault_id} not found")
        encrypted_payload = sample_file.read_bytes()
        defanged_bytes = self._cipher.decrypt(encrypted_payload)
        return self._refang(defanged_bytes)

    def get_metadata_by_vault_id(self, vault_id: str) -> Optional[Dict[str, Any]]:
        """Look up metadata in registry by vault_id."""
        for reg in self._registry.values():
            if reg.get("vault_id") == vault_id:
                return reg
        return None
