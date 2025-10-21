import oqs
import time
from typing import Tuple, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
import logging

logger = logging.getLogger(__name__)


@dataclass
class CryptoConfig:
    """Cryptographic configuration"""
    kem_algorithm: str = "Kyber768"
    sig_algorithm: str = "Dilithium3"
    key_rotation_interval: int = 3600  # seconds
    

class PQCryptoEngine:
    """
    Post-Quantum Cryptography Engine using liboqs
    Clean separation: only handles crypto operations
    """
    
    def __init__(self, config: CryptoConfig):
        self.config = config
        self._initialize_algorithms()
        
        # Keys will be loaded or generated externally
        self.kem_public_key: Optional[bytes] = None
        self.kem_secret_key: Optional[bytes] = None
        self.sig_public_key: Optional[bytes] = None
        self.sig_secret_key: Optional[bytes] = None
        
    def _initialize_algorithms(self):
        """Initialize KEM and signature algorithms"""
        try:
            self.kem = oqs.KeyEncapsulation(self.config.kem_algorithm)
            self.sig = oqs.Signature(self.config.sig_algorithm)
            logger.info(f"Initialized {self.config.kem_algorithm} + {self.config.sig_algorithm}")
        except Exception as e:
            logger.error(f"Failed to initialize algorithms: {e}")
            raise
    
    def generate_keypair(self) -> dict:
        """
        Generate new keypair
        Returns dict with all keys for external storage
        """
        # Generate KEM keypair
        self.kem_public_key = self.kem.generate_keypair()
        self.kem_secret_key = self.kem.secret_key
        
        # Generate signature keypair
        self.sig_public_key = self.sig.generate_keypair()
        self.sig_secret_key = self.sig.secret_key
        
        logger.info("Generated new keypair")
        
        return {
            'kem_public': self.kem_public_key,
            'kem_secret': self.kem_secret_key,
            'sig_public': self.sig_public_key,
            'sig_secret': self.sig_secret_key
        }
    
    def load_keys(self, kem_public: bytes, kem_secret: bytes,
                  sig_public: bytes, sig_secret: bytes):
        """Load existing keys"""
        self.kem_public_key = kem_public
        self.kem_secret_key = kem_secret
        self.sig_public_key = sig_public
        self.sig_secret_key = sig_secret
        
        # Set keys in oqs objects
        self.kem.secret_key = kem_secret
        self.sig.secret_key = sig_secret
        
        logger.info("Loaded existing keys")
    
    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate shared secret using peer's public key
        Returns (ciphertext, shared_secret)
        """
        ciphertext, shared_secret = self.kem.encap_secret(peer_public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret from ciphertext"""
        return self.kem.decap_secret(ciphertext)
    
    def sign(self, message: bytes) -> bytes:
        """Sign message with private key"""
        return self.sig.sign(message)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature with public key"""
        try:
            temp_sig = oqs.Signature(self.config.sig_algorithm)
            # verify() prend 3 arguments: message, signature, public_key
            is_valid = temp_sig.verify(message, signature, public_key)
            return is_valid
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def get_public_keys(self) -> dict:
        """Get public keys for transmission"""
        return {
            'kem_public': self.kem_public_key,
            'sig_public': self.sig_public_key
        }


class SymmetricCrypto:
    """
    AES-GCM encryption using PQ-derived shared secret
    Supports key rotation for long-lived connections
    """
    
    def __init__(self, shared_secret: bytes, rotation_interval: int = 3600):
        self.shared_secret = shared_secret
        self.rotation_interval = rotation_interval
        self.key_creation_time = time.time()
        self.key = self._derive_key(shared_secret)
        self.rotation_count = 0
    
    def _derive_key(self, context: bytes) -> bytes:
        """Derive AES key from shared secret using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pqsecure-sync-aes-key',
            backend=default_backend()
        )
        return hkdf.derive(context)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with AES-GCM"""
        nonce = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    def decrypt(self, ciphertext_bundle: bytes) -> bytes:
        """Decrypt AES-GCM ciphertext"""
        nonce = ciphertext_bundle[:12]
        tag = ciphertext_bundle[12:28]
        ciphertext = ciphertext_bundle[28:]
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def should_rotate_key(self) -> bool:
        """Check if key should be rotated"""
        elapsed = time.time() - self.key_creation_time
        return elapsed > self.rotation_interval
    
    def rotate_key(self) -> bytes:
        """
        Rotate encryption key using new context
        Returns new context for peer synchronization
        """
        self.rotation_count += 1
        new_context = self.shared_secret + self.rotation_count.to_bytes(4, 'big')
        self.key = self._derive_key(new_context)
        self.key_creation_time = time.time()
        
        logger.info(f"Key rotated (count: {self.rotation_count})")
        return new_context


class CryptoMetrics:
    """
    Separate metrics collector using decorator pattern
    Addresses critique about mixing concerns
    """
    
    def __init__(self):
        self.kem_keygen_time_ms = 0.0
        self.sig_keygen_time_ms = 0.0
        self.kem_encaps_time_ms = 0.0
        self.kem_decaps_time_ms = 0.0
        self.sig_sign_time_ms = 0.0
        self.sig_verify_time_ms = 0.0
        self.handshake_time_ms = 0.0
        self.key_sizes = {}
    
    def measure_keygen(self, engine: PQCryptoEngine) -> dict:
        """Measure key generation performance"""
        start = time.perf_counter()
        keys = engine.generate_keypair()
        self.kem_keygen_time_ms = (time.perf_counter() - start) * 1000
        
        self.key_sizes = {
            'kem_public': len(keys['kem_public']),
            'sig_public': len(keys['sig_public'])
        }
        
        return keys
    
    def measure_encapsulation(self, engine: PQCryptoEngine, 
                             peer_key: bytes) -> Tuple[bytes, bytes]:
        """Measure encapsulation performance"""
        start = time.perf_counter()
        result = engine.encapsulate(peer_key)
        self.kem_encaps_time_ms = (time.perf_counter() - start) * 1000
        return result
    
    def measure_decapsulation(self, engine: PQCryptoEngine, 
                             ciphertext: bytes) -> bytes:
        """Measure decapsulation performance"""
        start = time.perf_counter()
        result = engine.decapsulate(ciphertext)
        self.kem_decaps_time_ms = (time.perf_counter() - start) * 1000
        return result
    
    def get_metrics(self) -> dict:
        """Get all collected metrics"""
        return {
            'kem_keygen_time_ms': self.kem_keygen_time_ms,
            'sig_keygen_time_ms': self.sig_keygen_time_ms,
            'kem_encaps_time_ms': self.kem_encaps_time_ms,
            'kem_decaps_time_ms': self.kem_decaps_time_ms,
            'sig_sign_time_ms': self.sig_sign_time_ms,
            'sig_verify_time_ms': self.sig_verify_time_ms,
            'handshake_time_ms': self.handshake_time_ms,
            **self.key_sizes
        }
