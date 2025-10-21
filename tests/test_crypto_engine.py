"""Unit tests for cryptography engine"""

import pytest
from src.crypto.engine import PQCryptoEngine, CryptoConfig, SymmetricCrypto


class TestPQCryptoEngine:
    """Test PQ cryptography operations"""
    
    @pytest.fixture
    def crypto_config(self):
        return CryptoConfig(
            kem_algorithm="Kyber768",
            sig_algorithm="Dilithium3"
        )
    
    @pytest.fixture
    def crypto_engine(self, crypto_config):
        return PQCryptoEngine(crypto_config)
    
    def test_initialization(self, crypto_engine):
        """Test engine initialization"""
        assert crypto_engine.kem is not None
        assert crypto_engine.sig is not None
    
    def test_keypair_generation(self, crypto_engine):
        """Test keypair generation"""
        keys = crypto_engine.generate_keypair()
        
        assert 'kem_public' in keys
        assert 'kem_secret' in keys
        assert 'sig_public' in keys
        assert 'sig_secret' in keys
        
        assert len(keys['kem_public']) > 0
        assert len(keys['sig_public']) > 0
    
    def test_encapsulation_decapsulation(self, crypto_engine):
        """Test KEM encapsulation and decapsulation"""
        crypto_engine.generate_keypair()
        
        # Create peer engine
        peer_engine = PQCryptoEngine(crypto_engine.config)
        peer_engine.generate_keypair()
        
        # Encapsulate with peer's public key
        ciphertext, shared_secret1 = crypto_engine.encapsulate(
            peer_engine.kem_public_key
        )
        
        # Decapsulate on peer side
        shared_secret2 = peer_engine.decapsulate(ciphertext)
        
        # Shared secrets must match
        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) == 32  # 256 bits


class TestSymmetricCrypto:
    """Test symmetric encryption"""
    
    @pytest.fixture
    def symmetric_crypto(self):
        shared_secret = b"0" * 32
        return SymmetricCrypto(shared_secret)
    
    def test_encryption_decryption(self, symmetric_crypto):
        """Test basic encryption and decryption"""
        plaintext = b"Hello, World! This is a test message."
        
        ciphertext = symmetric_crypto.encrypt(plaintext)
        assert ciphertext != plaintext
        
        decrypted = symmetric_crypto.decrypt(ciphertext)
        assert decrypted == plaintext
