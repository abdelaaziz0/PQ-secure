import json
import hashlib
from pathlib import Path
from typing import Optional, Dict
import secrets
import logging

logger = logging.getLogger(__name__)


class KeyStore:
    """
    Manages persistent storage of cryptographic keys
    Addresses critique about ephemeral identities
    """
    
    def __init__(self, keys_dir: Path):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Secure file permissions
        try:
            import os
            os.chmod(self.keys_dir, 0o700)
        except:
            pass
        
        self.kem_key_file = self.keys_dir / "kem_keypair.bin"
        self.sig_key_file = self.keys_dir / "sig_keypair.bin"
        self.identity_file = self.keys_dir / "identity.json"
    
    def load_keys(self) -> Optional[Dict]:
        """Load existing keys from disk"""
        if not self._keys_exist():
            return None
        
        try:
            # Load KEM keys
            with open(self.kem_key_file, 'rb') as f:
                kem_data = f.read()
            
            # Parse: 4 bytes length + public key + secret key
            pub_len = int.from_bytes(kem_data[:4], 'big')
            kem_public = kem_data[4:4+pub_len]
            kem_secret = kem_data[4+pub_len:]
            
            # Load signature keys
            with open(self.sig_key_file, 'rb') as f:
                sig_data = f.read()
            
            pub_len = int.from_bytes(sig_data[:4], 'big')
            sig_public = sig_data[4:4+pub_len]
            sig_secret = sig_data[4+pub_len:]
            
            # Load identity
            with open(self.identity_file, 'r') as f:
                identity_data = json.load(f)
            
            logger.info(f"Loaded keys from {self.keys_dir}")
            
            return {
                'kem_public': kem_public,
                'kem_secret': kem_secret,
                'sig_public': sig_public,
                'sig_secret': sig_secret,
                'identity': identity_data['identity'],
                'created_at': identity_data['created_at']
            }
            
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")
            return None
    
    def save_keys(self, keys: Dict, identity: str, metadata: Dict = None):
        """Save keys to disk with secure permissions"""
        try:
            # Save KEM keys
            kem_data = (
                len(keys['kem_public']).to_bytes(4, 'big') +
                keys['kem_public'] +
                keys['kem_secret']
            )
            with open(self.kem_key_file, 'wb') as f:
                f.write(kem_data)
            
            # Save signature keys
            sig_data = (
                len(keys['sig_public']).to_bytes(4, 'big') +
                keys['sig_public'] +
                keys['sig_secret']
            )
            with open(self.sig_key_file, 'wb') as f:
                f.write(sig_data)
            
            # Save identity
            identity_data = {
                'identity': identity,
                'created_at': metadata.get('created_at') if metadata else None,
                'kem_algorithm': metadata.get('kem_algorithm') if metadata else 'Kyber768',
                'sig_algorithm': metadata.get('sig_algorithm') if metadata else 'Dilithium3'
            }
            
            with open(self.identity_file, 'w') as f:
                json.dump(identity_data, f, indent=2)
            
            # Set secure permissions
            import os
            os.chmod(self.kem_key_file, 0o600)
            os.chmod(self.sig_key_file, 0o600)
            os.chmod(self.identity_file, 0o600)
            
            logger.info(f"Saved keys to {self.keys_dir}")
            
        except Exception as e:
            logger.error(f"Failed to save keys: {e}")
            raise
    
    def generate_and_store(self, crypto_engine) -> Dict:
        """Generate new keypair and store persistently"""
        import time
        
        keys = crypto_engine.generate_keypair()
        
        # Generate unique identity from public key
        identity = self._generate_identity(keys['sig_public'])
        
        metadata = {
            'created_at': time.time(),
            'kem_algorithm': crypto_engine.config.kem_algorithm,
            'sig_algorithm': crypto_engine.config.sig_algorithm
        }
        
        self.save_keys(keys, identity, metadata)
        
        return {
            **keys,
            'identity': identity,
            'created_at': metadata['created_at']
        }
    
    def _generate_identity(self, public_key: bytes) -> str:
        """
        Generate unique identity from public key
        Format: pqsync-<hash>
        """
        key_hash = hashlib.sha256(public_key).hexdigest()[:16]
        return f"pqsync-{key_hash}"
    
    def _keys_exist(self) -> bool:
        """Check if key files exist"""
        return (
            self.kem_key_file.exists() and
            self.sig_key_file.exists() and
            self.identity_file.exists()
        )
    
    def delete_keys(self):
        """Securely delete keys"""
        import os
        
        for file in [self.kem_key_file, self.sig_key_file, self.identity_file]:
            if file.exists():
                # Overwrite before deletion
                size = file.stat().st_size
                with open(file, 'wb') as f:
                    f.write(secrets.token_bytes(size))
                os.remove(file)
        
        logger.info(f"Deleted keys from {self.keys_dir}")
    
    def backup_keys(self, backup_path: Path):
        """Create encrypted backup of keys"""
        # TODO: Implement encrypted backup
        pass
    
    def restore_keys(self, backup_path: Path):
        """Restore keys from encrypted backup"""
        # TODO: Implement restore from backup
        pass
