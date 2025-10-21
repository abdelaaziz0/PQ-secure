"""Test persistent key storage"""

import pytest
from src.crypto.keystore import KeyStore
from src.crypto.engine import PQCryptoEngine, CryptoConfig


class TestKeyStore:
    """Test key persistence"""
    
    def test_key_storage_and_loading(self, temp_keys_dir):
        """Test saving and loading keys"""
        keystore = KeyStore(temp_keys_dir)
        
        # Generate and store keys
        config = CryptoConfig()
        engine = PQCryptoEngine(config)
        
        stored_keys = keystore.generate_and_store(engine)
        
        assert 'kem_public' in stored_keys
        assert 'identity' in stored_keys
        assert stored_keys['identity'].startswith('pqsync-')
        
        # Load keys
        loaded_keys = keystore.load_keys()
        assert loaded_keys is not None
        assert loaded_keys['identity'] == stored_keys['identity']
    
    def test_keys_dont_exist_initially(self, temp_keys_dir):
        """Test that load returns None when no keys exist"""
        keystore = KeyStore(temp_keys_dir)
        assert keystore.load_keys() is None
