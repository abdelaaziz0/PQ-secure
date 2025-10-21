"""
crypto/trust.py - Trust Model and Identity Verification
Addresses critique: implement stronger trust model to defeat MITM
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Optional, Tuple, Dict
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class TrustedIdentity:
    """Trusted peer identity"""
    identity: str
    sig_public_key: str  # hex
    kem_public_key: str  # hex
    first_seen: float
    last_seen: float
    connection_count: int
    hostname: str
    fingerprint: str
    metadata: dict


class TrustStore:
    """
    Manages trusted peer identities with TOFU model
    Addresses critique: defeat first-connection MITM attacks
    """
    
    def __init__(self, trust_dir: Path):
        self.trust_dir = Path(trust_dir)
        self.trust_dir.mkdir(parents=True, exist_ok=True)
        
        self.trust_file = self.trust_dir / "trusted_hosts.json"
        self.trusted_identities: Dict[str, TrustedIdentity] = self._load_trusted()
    
    def _load_trusted(self) -> Dict[str, TrustedIdentity]:
        """Load trusted identities from disk"""
        if not self.trust_file.exists():
            return {}
        
        try:
            with open(self.trust_file, 'r') as f:
                data = json.load(f)
            
            return {
                k: TrustedIdentity(**v) 
                for k, v in data.items()
            }
        except Exception as e:
            logger.error(f"Failed to load trust store: {e}")
            return {}
    
    def _save_trusted(self):
        """Save trusted identities to disk"""
        data = {
            k: asdict(v) 
            for k, v in self.trusted_identities.items()
        }
        
        with open(self.trust_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def verify_identity(self, identity: str, sig_public_key: bytes,
                       kem_public_key: bytes, hostname: str) -> Tuple[Optional[bool], str]:
        """
        Verify peer identity against trust store
        Returns (is_trusted, reason)
        - True: identity is trusted and verified
        - False: identity mismatch (possible MITM)
        - None: new identity (TOFU decision needed)
        """
        if identity not in self.trusted_identities:
            return None, "New identity (TOFU required)"
        
        trusted = self.trusted_identities[identity]
        
        # Verify public keys match
        if trusted.sig_public_key != sig_public_key.hex():
            return False, "Signature public key mismatch - POSSIBLE MITM"
        
        if trusted.kem_public_key != kem_public_key.hex():
            return False, "KEM public key mismatch - POSSIBLE MITM"
        
        # Update last seen
        trusted.last_seen = time.time()
        trusted.connection_count += 1
        self._save_trusted()
        
        logger.info(f"Verified trusted identity: {identity}")
        return True, "Identity verified"
    
    def trust_on_first_use(self, identity: str, sig_public_key: bytes,
                          kem_public_key: bytes, hostname: str,
                          metadata: dict = None):
        """
        Trust a new identity (TOFU model)
        User should verify fingerprint out-of-band for security
        """
        fingerprint = self.get_host_fingerprint(sig_public_key)
        
        trusted = TrustedIdentity(
            identity=identity,
            sig_public_key=sig_public_key.hex(),
            kem_public_key=kem_public_key.hex(),
            first_seen=time.time(),
            last_seen=time.time(),
            connection_count=1,
            hostname=hostname,
            fingerprint=fingerprint,
            metadata=metadata or {}
        )
        
        self.trusted_identities[identity] = trusted
        self._save_trusted()
        
        logger.warning(f"TOFU: Trusted new identity {identity}")
        logger.warning(f"Fingerprint: {fingerprint}")
        logger.warning("Verify this fingerprint out-of-band for security!")
    
    def get_host_fingerprint(self, sig_public_key: bytes) -> str:
        """
        Generate human-readable fingerprint for out-of-band verification
        Format: XX:XX:XX:XX:XX:XX:XX:XX
        """
        key_hash = hashlib.sha256(sig_public_key).digest()
        fingerprint = ':'.join(f'{b:02X}' for b in key_hash[:8])
        return fingerprint
    
    def revoke_identity(self, identity: str, reason: str = ""):
        """Revoke trust for an identity"""
        if identity in self.trusted_identities:
            del self.trusted_identities[identity]
            self._save_trusted()
            logger.warning(f"Revoked trust for {identity}: {reason}")
    
    def list_trusted(self) -> Dict[str, TrustedIdentity]:
        """Get all trusted identities"""
        return self.trusted_identities.copy()
    
    def export_fingerprints(self, output_file: Path):
        """Export fingerprints for distribution"""
        fingerprints = {
            identity: {
                'fingerprint': trusted.fingerprint,
                'hostname': trusted.hostname,
                'first_seen': trusted.first_seen
            }
            for identity, trusted in self.trusted_identities.items()
        }
        
        with open(output_file, 'w') as f:
            json.dump(fingerprints, f, indent=2)
        
        logger.info(f"Exported fingerprints to {output_file}")
    
    def import_trusted_fingerprint(self, identity: str, fingerprint: str,
                                  sig_public_key: bytes, kem_public_key: bytes,
                                  hostname: str):
        """
        Import pre-shared trusted fingerprint
        This is the recommended way to defeat MITM on first connection
        """
        calculated_fp = self.get_host_fingerprint(sig_public_key)
        
        if calculated_fp != fingerprint:
            raise ValueError(
                f"Fingerprint mismatch! Expected {fingerprint}, "
                f"got {calculated_fp}"
            )
        
        self.trust_on_first_use(
            identity, sig_public_key, kem_public_key, hostname,
            {'pre_shared': True, 'verified_fingerprint': fingerprint}
        )
        
        logger.info(f"Imported pre-shared trusted identity: {identity}")


class SimpleCertificateAuthority:
    """
    Simple CA for more scalable trust model
    Alternative to TOFU for larger deployments
    """
    
    def __init__(self, ca_dir: Path):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        
        self.ca_key_file = self.ca_dir / "ca_key.bin"
        self.ca_cert_file = self.ca_dir / "ca_cert.json"
        
    def create_ca(self, crypto_engine):
        """Create new CA with PQ signature key"""
        ca_keys = crypto_engine.generate_keypair()
        
        # Store CA private key
        with open(self.ca_key_file, 'wb') as f:
            f.write(ca_keys['sig_secret'])
        
        # Create CA certificate
        ca_cert = {
            'type': 'ca',
            'public_key': ca_keys['sig_public'].hex(),
            'algorithm': crypto_engine.config.sig_algorithm,
            'created_at': time.time(),
            'issuer': 'self-signed'
        }
        
        with open(self.ca_cert_file, 'w') as f:
            json.dump(ca_cert, f, indent=2)
        
        import os
        os.chmod(self.ca_key_file, 0o600)
        
        logger.info("Created CA certificate")
        return ca_cert
    
    def sign_certificate(self, identity: str, sig_public_key: bytes,
                        crypto_engine) -> dict:
        """Sign a certificate for an identity"""
        # Load CA key
        with open(self.ca_key_file, 'rb') as f:
            ca_key = f.read()
        
        # Create certificate
        cert = {
            'type': 'identity',
            'identity': identity,
            'public_key': sig_public_key.hex(),
            'issued_at': time.time(),
            'valid_until': time.time() + (365 * 24 * 60 * 60),  # 1 year
            'algorithm': crypto_engine.config.sig_algorithm
        }
        
        # Sign certificate
        cert_data = json.dumps(cert, sort_keys=True).encode()
        
        # Temporarily set CA key for signing
        original_key = crypto_engine.sig_secret_key
        crypto_engine.sig.secret_key = ca_key
        signature = crypto_engine.sign(cert_data)
        crypto_engine.sig.secret_key = original_key
        
        cert['signature'] = signature.hex()
        
        return cert
    
    def verify_certificate(self, cert: dict, crypto_engine) -> bool:
        """Verify certificate signature"""
        with open(self.ca_cert_file, 'r') as f:
            ca_cert = json.load(f)
        
        ca_pubkey = bytes.fromhex(ca_cert['public_key'])
        
        # Extract signature
        signature = bytes.fromhex(cert['signature'])
        
        # Verify
        cert_copy = {k: v for k, v in cert.items() if k != 'signature'}
        cert_data = json.dumps(cert_copy, sort_keys=True).encode()
        
        return crypto_engine.verify(cert_data, signature, ca_pubkey)
