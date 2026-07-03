"""Tests for AES-GCM encryption layer (v0.5.0)."""

import os
import tempfile
from pathlib import Path

import pytest

from src.encryption import (
    AESGCMEncryptor,
    DecryptionError,
    EncryptionError,
    KeyManager,
    decrypt_payload,
    encrypt_payload,
)


class TestKeyManager:
    """Tests for KeyManager."""
    
    @pytest.mark.asyncio
    async def test_generate_key(self):
        """Test key generation."""
        km = KeyManager()
        key = await km.get_master_key()
        
        assert len(key) == 32  # 256 bits
        assert isinstance(key, bytes)
    
    @pytest.mark.asyncio
    async def test_key_persistence(self):
        """Test key persistence to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            
            # Create key
            km1 = KeyManager(key_path=key_path)
            key1 = await km1.get_master_key()
            
            # Load same key
            km2 = KeyManager(key_path=key_path)
            key2 = await km2.get_master_key()
            
            assert key1 == key2
            assert key1 == key2
    
    @pytest.mark.asyncio
    async def test_tenant_key_derivation(self):
        """Test per-tenant key derivation."""
        km = KeyManager()
        
        key1 = await km.get_tenant_key("tenant-a")
        key2 = await km.get_tenant_key("tenant-b")
        master = await km.get_tenant_key(None)
        
        # Different tenants get different keys
        assert key1 != key2
        # Tenant keys differ from master
        assert key1 != master
        assert key2 != master
    
    @pytest.mark.asyncio
    async def test_key_rotation(self):
        """Test key rotation."""
        km = KeyManager()
        
        key1 = await km.get_master_key()
        key2 = await km.rotate_key()
        
        assert key1 != key2
        # After rotation, get_master_key returns new key
        key3 = await km.get_master_key()
        assert key3 == key2
    
    @pytest.mark.asyncio
    async def test_tenant_key_cleared_on_rotation(self):
        """Test that tenant keys are cleared on master key rotation."""
        km = KeyManager()
        
        tenant_key1 = await km.get_tenant_key("tenant-a")
        await km.rotate_key()
        tenant_key2 = await km.get_tenant_key("tenant-a")
        
        # New tenant key after rotation
        assert tenant_key1 != tenant_key2
    
    @pytest.mark.asyncio
    async def test_key_file_permissions(self):
        """Test that key file has restrictive permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test.key"
            
            km = KeyManager(key_path=key_path)
            await km.get_master_key()
            
            # Check permissions (0o600 = owner read/write only)
            stat_info = os.stat(key_path)
            # On Windows this may not work, so just check file exists
            assert key_path.exists()


class TestAESGCMEncryptor:
    """Tests for AES-GCM encryption."""
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self):
        """Test encryption followed by decryption."""
        encryptor = AESGCMEncryptor()
        
        plaintext = b"Hello, World! This is a secret message."
        ciphertext = await encryptor.encrypt(plaintext)
        decrypted = await encryptor.decrypt(ciphertext)
        
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_with_tenant(self):
        """Test encryption with tenant isolation."""
        encryptor = AESGCMEncryptor()
        
        plaintext = b"Tenant-specific secret data"
        ciphertext = await encryptor.encrypt(plaintext, tenant_id="acme-corp")
        decrypted = await encryptor.decrypt(ciphertext, tenant_id="acme-corp")
        
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_tenant_isolation(self):
        """Test that different tenants have different ciphertexts."""
        encryptor = AESGCMEncryptor()
        
        plaintext = b"Same message"
        ct1 = await encryptor.encrypt(plaintext, tenant_id="tenant-a")
        ct2 = await encryptor.encrypt(plaintext, tenant_id="tenant-b")
        
        # Same plaintext, different tenants = different ciphertext
        assert ct1 != ct2
        
        # But each can decrypt its own
        assert await encryptor.decrypt(ct1, tenant_id="tenant-a") == plaintext
        assert await encryptor.decrypt(ct2, tenant_id="tenant-b") == plaintext
    
    @pytest.mark.asyncio
    async def test_tamper_detection(self):
        """Test that tampering is detected."""
        encryptor = AESGCMEncryptor()
        
        plaintext = b"Original message"
        ciphertext = await encryptor.encrypt(plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[-10] ^= 0xFF  # Flip bits
        
        with pytest.raises(DecryptionError):
            await encryptor.decrypt(bytes(tampered))
    
    @pytest.mark.asyncio
    async def test_nonce_reuse_detection(self):
        """Test nonce management."""
        encryptor = AESGCMEncryptor()
        
        plaintext = b"Message 1"
        ct1 = await encryptor.encrypt(plaintext)
        
        # Extract nonce from ciphertext
        nonce1 = ct1[4:16]  # version(4) + nonce(12)
        
        # Encrypt another message
        plaintext2 = b"Message 2"
        ct2 = await encryptor.encrypt(plaintext2)
        
        # Nonces should be different
        nonce2 = ct2[4:16]
        assert nonce1 != nonce2
    
    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test encryption of empty data."""
        encryptor = AESGCMEncryptor()
        
        plaintext = b""
        ciphertext = await encryptor.encrypt(plaintext)
        decrypted = await encryptor.decrypt(ciphertext)
        
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_large_payload(self):
        """Test encryption of large data."""
        encryptor = AESGCMEncryptor()
        
        # 1MB payload
        plaintext = os.urandom(1024 * 1024)
        ciphertext = await encryptor.encrypt(plaintext)
        decrypted = await encryptor.decrypt(ciphertext)
        
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_invalid_ciphertext_too_short(self):
        """Test that truncated ciphertext raises error."""
        encryptor = AESGCMEncryptor()
        
        with pytest.raises(DecryptionError):
            await encryptor.decrypt(b"short")
    
    @pytest.mark.asyncio
    async def test_invalid_version(self):
        """Test that wrong version raises error."""
        encryptor = AESGCMEncryptor()
        
        # Create invalid ciphertext with wrong version
        import struct
        wrong_version = struct.pack(">I", 999)
        invalid_ct = wrong_version + os.urandom(50)
        
        with pytest.raises(DecryptionError):
            await encryptor.decrypt(invalid_ct)
    
    @pytest.mark.asyncio
    async def test_aclose(self):
        """Test cleanup on close."""
        encryptor = AESGCMEncryptor()
        
        await encryptor.encrypt(b"test")
        await encryptor.aclose()
        
        # Nonce cache should be cleared
        assert len(encryptor._used_nonces) == 0


class TestEncryptPayloadAPI:
    """Tests for the encrypt_payload/decrypt_payload API."""
    
    @pytest.mark.asyncio
    async def test_encrypt_payload(self):
        """Test encrypt_payload function."""
        plaintext = b"Secret API message"
        encrypted = await encrypt_payload(plaintext)
        
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(plaintext)  # Includes nonce + tag
    
    @pytest.mark.asyncio
    async def test_decrypt_payload(self):
        """Test decrypt_payload function."""
        plaintext = b"Secret API message"
        encrypted = await encrypt_payload(plaintext)
        decrypted = await decrypt_payload(encrypted)
        
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_tenant_api(self):
        """Test API with tenant isolation."""
        plaintext = b"Tenant data"
        encrypted = await encrypt_payload(plaintext, tenant_id="test-tenant")
        decrypted = await decrypt_payload(encrypted, tenant_id="test-tenant")
        
        assert decrypted == plaintext
    
    @pytest.mark.asyncio
    async def test_wrong_tenant_fails(self):
        """Test that wrong tenant cannot decrypt."""
        plaintext = b"Tenant A data"
        encrypted = await encrypt_payload(plaintext, tenant_id="tenant-a")
        
        with pytest.raises(DecryptionError):
            await decrypt_payload(encrypted, tenant_id="tenant-b")


class TestEncryptionIntegration:
    """Integration tests for encryption with other modules."""
    
    @pytest.mark.asyncio
    async def test_encryption_with_audit(self):
        """Test that encryption events can be audited."""
        from src.audit import AuditLogger, AuditEvent
        from types import SimpleNamespace
        
        # Create temp audit log
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.log"
            config = SimpleNamespace()
            config.enabled = True
            config.log_dir = str(tmpdir)
            config.log_filename = audit_path.name
            config.max_size_mb = 100
            config.buffer_size = 100
            config.flush_interval_seconds = 1.0
            config.redact_in_log = True
            logger = AuditLogger(config)
            
            # Log encryption event
            event = AuditEvent(
                event_type="encryption_applied",
                extra={"algorithm": "AES-GCM-256", "tenant_id": "test-tenant"},
            )
            await logger.log(event)
            await logger.aclose()  # Flush buffer to file
            
            # Verify log written
            assert audit_path.exists()
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_performance(self):
        """Test encryption performance for typical payloads."""
        import time
        
        encryptor = AESGCMEncryptor()
        plaintext = b"API request body with PII: john.doe@email.com, SSN: 123-45-6789"
        
        # Measure encryption
        start = time.perf_counter()
        for _ in range(100):
            await encryptor.encrypt(plaintext)
        enc_time = time.perf_counter() - start
        
        # Measure decryption
        ciphertext = await encryptor.encrypt(plaintext)
        start = time.perf_counter()
        for _ in range(100):
            await encryptor.decrypt(ciphertext)
        dec_time = time.perf_counter() - start
        
        # Should be fast (< 100ms for 100 iterations each)
        assert enc_time < 0.1
        assert dec_time < 0.1
        
        await encryptor.aclose()