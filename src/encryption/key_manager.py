"""Key management for AES-GCM encryption.

Provides:
- Key generation (256-bit)
- Key loading from file
- Key rotation
- Per-tenant key isolation
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import aiofiles
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class KeyManager:
    """Manages encryption keys for AES-GCM.

    Supports:
    - Master key from file or generated
    - Per-tenant derived keys
    - Key rotation
    - Secure key storage
    """

    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits
    SALT_SIZE = 16

    def __init__(self, key_path: str | Path | None = None):
        """Initialize key manager.

        Args:
            key_path: Path to encryption key file. If None, generates ephemeral key.
        """
        self._key_path = Path(key_path) if key_path else None
        self._master_key: bytes | None = None
        self._tenant_keys: dict[str, bytes] = {}

    async def _load_or_generate_key(self) -> bytes:
        """Load key from file or generate new one."""
        if self._key_path and self._key_path.exists():
            async with aiofiles.open(self._key_path, "rb") as f:
                key_bytes: bytes = await f.read()
                if len(key_bytes) == self.KEY_SIZE:
                    return key_bytes

        # Generate new key
        key = secrets.token_bytes(self.KEY_SIZE)

        if self._key_path:
            # Ensure parent directory exists
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self._key_path, "wb") as f:
                await f.write(key)
            # Set restrictive permissions (owner read/write only)
            os.chmod(self._key_path, 0o600)

        return key

    async def get_master_key(self) -> bytes:
        """Get or generate master encryption key."""
        if self._master_key is None:
            self._master_key = await self._load_or_generate_key()
        return self._master_key

    def _derive_salt_from_tenant(self, tenant_id: str) -> bytes:
        """Derive deterministic salt from tenant ID using HMAC."""
        h = hmac.HMAC(b"dataguard-tenant-salt-v1", hashes.SHA256())
        h.update(tenant_id.encode("utf-8"))
        return h.finalize()[: self.SALT_SIZE]

    async def get_tenant_key(self, tenant_id: str | None = None) -> bytes:
        """Get encryption key for tenant.

        If tenant_id is None, returns master key.
        Otherwise derives a key from master using HKDF-like approach.

        Args:
            tenant_id: Tenant identifier for key isolation

        Returns:
            256-bit encryption key
        """
        if tenant_id is None:
            return await self.get_master_key()

        if tenant_id not in self._tenant_keys:
            # Derive tenant-specific key from master
            master = await self.get_master_key()
            salt = self._derive_salt_from_tenant(tenant_id)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=salt,
                iterations=100000,
            )
            self._tenant_keys[tenant_id] = kdf.derive(master)

        return self._tenant_keys[tenant_id]

    async def rotate_key(self) -> bytes:
        """Rotate master key.

        Generates new key and updates key file.
        Returns new key for immediate use.
        """
        new_key = secrets.token_bytes(self.KEY_SIZE)
        self._master_key = new_key

        if self._key_path:
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self._key_path, "wb") as f:
                await f.write(new_key)
            os.chmod(self._key_path, 0o600)

        # Clear tenant keys to force re-derivation
        self._tenant_keys.clear()

        return new_key

    def clear_all_keys(self) -> None:
        """Clear all cached keys from memory."""
        self._master_key = None
        self._tenant_keys.clear()


class EncryptionError(Exception):
    """Base encryption error."""

    pass


class DecryptionError(EncryptionError):
    """Decryption failed."""

    pass
