"""Test trust model and identity verification"""

import pytest
from src.crypto.trust import TrustStore
from src.crypto.engine import PQCryptoEngine, CryptoConfig


class TestTrustStore:
    """Test trust store operations"""
    
    def test_new_identity_tofu(self, temp_dir):
        """Test Trust On First Use for new identity"""
        trust_store = TrustStore(temp_dir)
        
        engine = PQCryptoEngine(CryptoConfig())
        engine.generate_keypair()
        
        identity = "test-client"
        
        # First verification should return None (new identity)
        result, reason = trust_store.verify_identity(
            identity, engine.sig_public_key, engine.kem_public_key, "localhost"
        )
        assert result is None
        assert "TOFU" in reason
        
        # Trust the identity
        trust_store.trust_on_first_use(
            identity, engine.sig_public_key, engine.kem_public_key, "localhost"
        )
        
        # Second verification should succeed
        result, reason = trust_store.verify_identity(
            identity, engine.sig_public_key, engine.kem_public_key, "localhost"
        )
        assert result is True
    
    def test_fingerprint_generation(self, temp_dir):
        """Test fingerprint generation"""
        trust_store = TrustStore(temp_dir)
        
        engine = PQCryptoEngine(CryptoConfig())
        engine.generate_keypair()
        
        fingerprint = trust_store.get_host_fingerprint(engine.sig_public_key)
        
        # Should be colon-separated hex
        assert ':' in fingerprint
        parts = fingerprint.split(':')
        assert len(parts) == 8
