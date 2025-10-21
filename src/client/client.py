"""PQ-Secure Sync Client - Version corrigée"""

import asyncio
from pathlib import Path
import logging

from ..crypto.engine import PQCryptoEngine, CryptoConfig, SymmetricCrypto
from ..crypto.keystore import KeyStore
from ..crypto.trust import TrustStore
from ..network.protocol import Protocol, MessageType, PROTOCOL_VERSION
from ..network.transport import SecureTransport
from ..sync.engine import SyncEngine

logger = logging.getLogger(__name__)


class PQSyncClient:
    """Post-Quantum Secure Sync Client"""
    
    def __init__(self, host: str, port: int, sync_dir: Path,
                 keys_dir: Path, config: CryptoConfig):
        self.host = host
        self.port = port
        self.sync_dir = Path(sync_dir)
        self.keys_dir = Path(keys_dir)
        self.config = config
        
        self.keystore = KeyStore(self.keys_dir / "client")
        self.crypto_engine = PQCryptoEngine(config)
        self.trust_store = TrustStore(self.keys_dir / "trust")
        
        self._initialize_keys()
        self.sync_engine = SyncEngine(self.sync_dir, self.identity)
        
        self.protocol = Protocol()
        self.transport = SecureTransport(self.protocol)
    
    def _initialize_keys(self):
        """Load or generate client keys"""
        keys = self.keystore.load_keys()
        
        if not keys:
            logger.info("Generating new client keypair")
            keys = self.keystore.generate_and_store(self.crypto_engine)
        else:
            self.crypto_engine.load_keys(
                keys['kem_public'], keys['kem_secret'],
                keys['sig_public'], keys['sig_secret']
            )
        
        self.identity = keys['identity']
        logger.info(f"Client identity: {self.identity}")
    
    async def connect(self) -> bool:
        """Connect to server"""
        try:
            logger.info(f"Connecting to {self.host}:{self.port}")
            reader, writer = await asyncio.open_connection(self.host, self.port)
            self.transport.set_stream(reader, writer)
            
            if not await self._perform_handshake():
                raise ConnectionError("Handshake failed")
            
            logger.info("✓ Connected successfully")
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}", exc_info=True)
            return False
    
    async def _perform_handshake(self) -> bool:
        """Perform PQ handshake"""
        try:
            # Send INIT
            init_data = {
                'kem_public_key': self.crypto_engine.kem_public_key.hex(),
                'sig_public_key': self.crypto_engine.sig_public_key.hex(),
                'identity': self.identity,
                'kem_algorithm': self.config.kem_algorithm,
                'sig_algorithm': self.config.sig_algorithm
            }
            
            # Sign the handshake
            sig_data = init_data['kem_public_key'] + init_data['identity']
            init_data['signature'] = self.crypto_engine.sign(sig_data.encode()).hex()
            
            logger.debug("Sending HANDSHAKE_INIT...")
            await self.transport.send_message(MessageType.HANDSHAKE_INIT, init_data)
            
            # Receive RESPONSE
            logger.debug("Waiting for HANDSHAKE_RESPONSE...")
            msg_type, response = await self.transport.recv_message()
            logger.debug(f"Received message type: {msg_type}")
            
            if msg_type != MessageType.HANDSHAKE_RESPONSE:
                logger.error(f"Expected HANDSHAKE_RESPONSE, got {msg_type}")
                return False
            
            # Extract server info
            server_identity = response['identity']
            server_kem = bytes.fromhex(response['kem_public_key'])
            server_sig = bytes.fromhex(response['sig_public_key'])
            
            logger.info(f"Received handshake response from server: {server_identity}")
            
            # Verify trust
            trust_result, reason = self.trust_store.verify_identity(
                server_identity, server_sig, server_kem, self.host
            )
            
            if trust_result is None:
                fingerprint = self.trust_store.get_host_fingerprint(server_sig)
                logger.warning(f"⚠ NEW SERVER IDENTITY: {server_identity}")
                logger.warning(f"⚠ Fingerprint: {fingerprint}")
                logger.warning(f"⚠ Verify this fingerprint out-of-band before trusting!")
                
                self.trust_store.trust_on_first_use(
                    server_identity, server_sig, server_kem, self.host
                )
            elif not trust_result:
                raise ConnectionError(f"Server verification failed: {reason}")
            
            logger.info(f"✓ Server identity verified")
            
            # Decapsulate shared secret
            ciphertext = bytes.fromhex(response['ciphertext'])
            shared_secret = self.crypto_engine.decapsulate(ciphertext)
            logger.debug(f"✓ Decapsulated shared secret")
            
            # Préparer le chiffrement (mais NE PAS l'activer encore)
            symmetric_crypto = SymmetricCrypto(shared_secret)
            logger.debug("✓ Symmetric crypto prepared")
            
            # MAINTENANT on active le chiffrement
            self.transport.set_crypto(symmetric_crypto)
            logger.debug("✓ Symmetric crypto activated")
            
            # Send COMPLETE (sera chiffré)
            logger.debug("Sending HANDSHAKE_COMPLETE...")
            await self.transport.send_message(MessageType.HANDSHAKE_COMPLETE, {
                'status': 'success'
            })
            
            logger.info(f"✓ Handshake complete with {server_identity}")
            return True
            
        except Exception as e:
            logger.error(f"Handshake failed: {e}", exc_info=True)
            return False
    
    async def sync_files(self):
        """Synchronize files"""
        try:
            self.sync_engine.scan_directory()
            
            await self.transport.send_message(MessageType.FILE_SYNC_REQUEST, {
                'client_version': self.protocol.version
            })
            
            msg_type, response = await self.transport.recv_message()
            
            if msg_type == MessageType.FILE_SYNC_RESPONSE:
                logger.info("✓ Sync completed successfully")
            
        except Exception as e:
            logger.error(f"Sync failed: {e}", exc_info=True)
    
    async def run(self):
        """Main client loop"""
        if not await self.connect():
            return
        
        await self.sync_files()
        
        logger.info("Client running. Press Ctrl+C to stop.")
        
        try:
            while True:
                await asyncio.sleep(30)
                await self.transport.send_message(MessageType.HEARTBEAT, {})
        except KeyboardInterrupt:
            logger.info("Client shutting down")
