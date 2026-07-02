"""AES-GCM encryption layer for DataGuard Fortress.

Provides end-to-end encryption for PII scrubbed data with:
- 256-bit keys
- 96-bit nonces (unique per encryption)
- 128-bit authentication tags
- Per-tenant key isolation
- Key rotation support

Usage:
    from dataguard.encryption import encrypt_payload, decrypt_payload
    
    encrypted = await encrypt_payload(b"sensitive data", tenant_id="acme")
    decrypted = await decrypt_payload(encrypted, tenant_id="acme")
"""

from __future__ import annotations

from dataguard.encryption.aes_gcm import AESGCMEncryptor
from dataguard.encryption.key_manager import KeyManager

__all__ = ["AESGCMEncryptor", "KeyManager", "encrypt_payload", "decrypt_payload"]

# Global instances (initialized lazily)
_encryptor: AESGCMEncryptor | None = None
_key_manager: KeyManager | None = None


async def encrypt_payload(data: bytes, tenant_id: str | None = None) -> bytes:
    """Encrypt payload using AES-GCM.
    
    Args:
        data: Raw bytes to encrypt
        tenant_id: Optional tenant for per-tenant key isolation
        
    Returns:
        Encrypted bytes (nonce + ciphertext + tag)
        
    Raises:
        EncryptionError: If encryption fails
    """
    global _encryptor
    if _encryptor is None:
        _encryptor = AESGCMEncryptor()
    return await _encryptor.encrypt(data, tenant_id=tenant_id)


async def decrypt_payload(data: bytes, tenant_id: str | None = None) -> bytes:
    """Decrypt payload using AES-GCM.
    
    Args:
        data: Encrypted bytes (nonce + ciphertext + tag)
        tenant_id: Optional tenant for per-tenant key isolation
        
    Returns:
        Decrypted raw bytes
        
    Raises:
        DecryptionError: If decryption fails or tag verification fails
    """
    global _encryptor
    if _encryptor is None:
        _encryptor = AESGCMEncryptor()
    return await _encryptor.decrypt(data, tenant_id=tenant_id)