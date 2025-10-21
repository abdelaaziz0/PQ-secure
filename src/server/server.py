"""PQ-Secure Sync Server - Version corrigée"""

import asyncio
from pathlib import Path
from typing import Dict
import logging
from dataclasses import asdict

from ..crypto.engine import PQCryptoEngine, CryptoConfig, SymmetricCrypto
from ..crypto.keystore import KeyStore
from ..crypto.trust import TrustStore
from ..network.protocol import Protocol, MessageType, PROTOCOL_VERSION
from ..network.transport import SecureTransport
from ..sync.engine import SyncEngine

logger = logging.getLogger(__name__)


class PQSyncServer:
    """Post-Quantum Secure Sync Server"""
    
    def __init__(self, host: str, port: int, sync_dir: Path,
                 keys_dir: Path, config: CryptoConfig):
        self.host = host
        self.port = port
        self.sync_dir = Path(sync_dir)
        self.keys_dir = Path(keys_dir)
        self.config = config
        
        self.keystore = KeyStore(self.keys_dir / "server")
        self.crypto_engine = PQCryptoEngine(config)
        self.trust_store = TrustStore(self.keys_dir / "trust")
        
        self._initialize_keys()
        self.sync_engine = SyncEngine(self.sync_dir, self.identity)
        self.clients: Dict[str, Dict] = {}
    
    def _initialize_keys(self):
        """Load or generate server keys"""
        keys = self.keystore.load_keys()
        
        if not keys:
            logger.info("Generating new server keypair")
            keys = self.keystore.generate_and_store(self.crypto_engine)
        else:
            self.crypto_engine.load_keys(
                keys['kem_public'], keys['kem_secret'],
                keys['sig_public'], keys['sig_secret']
            )
        
        self.identity = keys['identity']
        fingerprint = self.trust_store.get_host_fingerprint(keys['sig_public'])
        
        logger.info(f"Server identity: {self.identity}")
        logger.info(f"Server fingerprint: {fingerprint}")
    
    async def handle_client(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter):
        """Handle client connection"""
        addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {addr}")
        
        protocol = Protocol()
        transport = SecureTransport(protocol)
        transport.set_stream(reader, writer)
        
        try:
            if not await self._perform_handshake(transport):
                raise ConnectionError("Handshake failed")
            
            while True:
                msg_type, payload = await transport.recv_message()
                
                if msg_type == MessageType.FILE_SYNC_REQUEST:
                    await self._handle_sync_request(transport)
                elif msg_type == MessageType.HEARTBEAT:
                    logger.debug(f"Heartbeat from {addr}")
                
        except asyncio.IncompleteReadError:
            logger.info(f"Client {addr} disconnected")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}", exc_info=True)
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _perform_handshake(self, transport: SecureTransport) -> bool:
        """Perform PQ handshake"""
        try:
            # Receive INIT
            logger.debug("Waiting for HANDSHAKE_INIT...")
            msg_type, init_payload = await transport.recv_message()
            logger.debug(f"Received message type: {msg_type}")
            logger.debug(f"Payload keys: {init_payload.keys()}")
            
            if msg_type != MessageType.HANDSHAKE_INIT:
                logger.error(f"Expected HANDSHAKE_INIT, got {msg_type}")
                return False
            
            # Extract client info
            client_kem = bytes.fromhex(init_payload['kem_public_key'])
            client_sig = bytes.fromhex(init_payload['sig_public_key'])
            client_identity = init_payload['identity']
            
            logger.info(f"Received handshake from client: {client_identity}")
            
            # Verify signature
            sig_data = init_payload['kem_public_key'] + init_payload['identity']
            signature = bytes.fromhex(init_payload['signature'])
            
            if not self.crypto_engine.verify(sig_data.encode(), signature, client_sig):
                logger.error("Client signature verification failed!")
                return False
            
            logger.info(f"✓ Client signature verified: {client_identity}")
            
            # Encapsulate shared secret
            ciphertext, shared_secret = self.crypto_engine.encapsulate(client_kem)
            logger.debug(f"Encapsulated shared secret, ciphertext size: {len(ciphertext)}")
            
            # Préparer le chiffrement (mais NE PAS l'activer encore)
            symmetric_crypto = SymmetricCrypto(shared_secret)
            logger.debug("✓ Symmetric crypto prepared")
            
            # Send RESPONSE (non chiffré)
            response_data = {
                'kem_public_key': self.crypto_engine.kem_public_key.hex(),
                'sig_public_key': self.crypto_engine.sig_public_key.hex(),
                'identity': self.identity,
                'ciphertext': ciphertext.hex()
            }
            
            # Sign response
            sig_data = response_data['kem_public_key'] + response_data['identity']
            response_data['signature'] = self.crypto_engine.sign(sig_data.encode()).hex()
            
            logger.debug("Sending HANDSHAKE_RESPONSE...")
            await transport.send_message(MessageType.HANDSHAKE_RESPONSE, response_data)
            
            # MAINTENANT on active le chiffrement
            transport.set_crypto(symmetric_crypto)
            logger.debug("✓ Symmetric crypto activated")
            
            # Wait for COMPLETE (sera chiffré)
            logger.debug("Waiting for HANDSHAKE_COMPLETE...")
            msg_type, complete = await transport.recv_message()
            
            if msg_type != MessageType.HANDSHAKE_COMPLETE:
                logger.error(f"Expected HANDSHAKE_COMPLETE, got {msg_type}")
                return False
            
            logger.info(f"✓ Handshake complete with {client_identity}")
            return True
            
        except Exception as e:
            logger.error(f"Handshake failed: {e}", exc_info=True)
            return False
    
    async def _handle_sync_request(self, transport: SecureTransport):
        """Handle file sync request"""
        self.sync_engine.scan_directory()
        
        response = {
            'file_index': {k: asdict(v) for k, v in self.sync_engine.file_index.items()},
            'tombstones': {}
        }
        
        await transport.send_message(MessageType.FILE_SYNC_RESPONSE, response)
        logger.info("Sent sync response")
    
    async def run(self):
        """Start server"""
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        
        addr = server.sockets[0].getsockname()
        logger.info(f"PQ-Secure Sync Server v2.0 listening on {addr}")
        
        async with server:
            await server.serve_forever()
