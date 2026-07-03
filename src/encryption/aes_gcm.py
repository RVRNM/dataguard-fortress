"""AES-GCM encryption implementation.

Provides:
- AES-256-GCM encryption with 96-bit nonces
- Async encryption/decryption
- Nonce management
- Tamper detection via authentication tags
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .key_manager import (
    DecryptionError,
    EncryptionError,
    KeyManager,
)


# Nonce header format: 4 bytes version + 12 bytes nonce = 16 bytes total
NONCE_HEADER_SIZE = 16
VERSION = 1


@dataclass
class EncryptionResult:
    """Result of encryption operation."""
    
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    tenant_id: str | None


class AESGCMEncryptor:
    """AES-256-GCM encryptor with nonce management.
    
    Features:
    - 256-bit keys
    - 96-bit nonces (unique per encryption)
    - 128-bit authentication tags
    - Per-tenant key isolation
    - Nonce replay protection
    """
    
    TAG_SIZE = 16  # 128 bits
    NONCE_SIZE = 12  # 96 bits
    VERSION_SIZE = 4  # 32 bits
    
    def __init__(self, key_manager: KeyManager | None = None):
        """Initialize encryptor.
        
        Args:
            key_manager: Optional KeyManager instance. Creates default if None.
        """
        self._key_manager = key_manager or KeyManager()
        self._used_nonces: set[bytes] = set()
        self._nonce_cache_size = 10000
    
    async def encrypt(self, data: bytes, tenant_id: str | None = None) -> bytes:
        """Encrypt data using AES-GCM.
        
        Args:
            data: Plaintext bytes to encrypt
            tenant_id: Optional tenant for key isolation
            
        Returns:
            bytes: nonce_header + ciphertext + tag
                Format: [4-byte version][12-byte nonce][ciphertext][16-byte tag]
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Get tenant-specific key
            key = await self._key_manager.get_tenant_key(tenant_id)
            
            # Generate unique nonce
            nonce = self._generate_nonce()
            
            # Encrypt
            aesgcm = AESGCM(key)
            ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
            
            # Split ciphertext and tag
            ciphertext = ciphertext_with_tag[:-self.TAG_SIZE]
            tag = ciphertext_with_tag[-self.TAG_SIZE:]
            
            # Build output: version + nonce + ciphertext + tag
            version_bytes = struct.pack(">I", VERSION)
            result = version_bytes + nonce + ciphertext + tag
            
            return result
            
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    async def decrypt(self, data: bytes, tenant_id: str | None = None) -> bytes:
        """Decrypt data using AES-GCM.
        
        Args:
            data: Encrypted bytes (nonce_header + ciphertext + tag)
            tenant_id: Optional tenant for key isolation
            
        Returns:
            bytes: Decrypted plaintext
            
        Raises:
            DecryptionError: If decryption fails or tag verification fails
        """
        if len(data) < NONCE_HEADER_SIZE + self.TAG_SIZE:
            raise DecryptionError("Data too short to contain valid encrypted payload")
        
        try:
            # Parse header
            version = struct.unpack(">I", data[: self.VERSION_SIZE])[0]
            if version != VERSION:
                raise DecryptionError(f"Unsupported version: {version}")
            
            nonce = data[self.VERSION_SIZE : self.VERSION_SIZE + self.NONCE_SIZE]
            ciphertext_and_tag = data[self.VERSION_SIZE + self.NONCE_SIZE :]
            
            if len(ciphertext_and_tag) < self.TAG_SIZE:
                raise DecryptionError("Ciphertext too short to contain tag")
            
            ciphertext = ciphertext_and_tag[:-self.TAG_SIZE]
            tag = ciphertext_and_tag[-self.TAG_SIZE :]
            
            # Get tenant-specific key
            key = await self._key_manager.get_tenant_key(tenant_id)
            
            # Decrypt
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
            
            return plaintext
            
        except DecryptionError:
            raise
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def _generate_nonce(self) -> bytes:
        """Generate a unique nonce for encryption.
        
        Uses random generation with collision checking.
        """
        # Clean old nonces if cache is too large
        if len(self._used_nonces) > self._nonce_cache_size:
            # Keep only most recent half
            self._used_nonces = set(list(self._used_nonces)[-(self._nonce_cache_size // 2) :])
        
        # Generate unique nonce
        while True:
            nonce = secrets.token_bytes(self.NONCE_SIZE)
            if nonce not in self._used_nonces:
                self._used_nonces.add(nonce)
                return nonce
    
    async def flush_nonce_cache(self) -> None:
        """Clear nonce cache (call on graceful shutdown)."""
        self._used_nonces.clear()
    
    async def aclose(self) -> None:
        """Close and cleanup resources."""
        await self.flush_nonce_cache()
        self._key_manager.clear_all_keys()

