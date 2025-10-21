"""Secure transport layer"""

import asyncio
import struct
import json
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class SecureTransport:
    """Secure transport with encryption"""
    
    def __init__(self, protocol=None):
        self.protocol = protocol
        self.symmetric_crypto = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
    
    def set_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Set network stream"""
        self.reader = reader
        self.writer = writer
    
    def set_crypto(self, symmetric_crypto):
        """Set encryption layer"""
        self.symmetric_crypto = symmetric_crypto
    
    async def send_message(self, msg_type, payload: dict):
        """Send message (encrypted if crypto available)"""
        if not self.writer:
            raise ValueError("No writer stream set")
        
        # Create message with proper structure
        message = {
            'type': msg_type.value if hasattr(msg_type, 'value') else msg_type,
            'payload': payload
        }
        
        # Serialize to JSON
        msg_bytes = json.dumps(message).encode('utf-8')
        
        # Encrypt if crypto is set up
        if self.symmetric_crypto:
            msg_bytes = self.symmetric_crypto.encrypt(msg_bytes)
        
        # Send with length prefix
        try:
            length_prefix = struct.pack('!I', len(msg_bytes))
            self.writer.write(length_prefix + msg_bytes)
            await self.writer.drain()
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise
    
    async def recv_message(self) -> Tuple:
        """Receive message (decrypt if crypto available)"""
        if not self.reader:
            raise ValueError("No reader stream set")
        
        try:
            # Read length prefix (4 bytes)
            length_bytes = await self.reader.readexactly(4)
            msg_length = struct.unpack('!I', length_bytes)[0]
            
            # Read message body
            msg_bytes = await self.reader.readexactly(msg_length)
            
            # Decrypt if crypto is available
            if self.symmetric_crypto:
                msg_bytes = self.symmetric_crypto.decrypt(msg_bytes)
            
            # Deserialize JSON
            message = json.loads(msg_bytes.decode('utf-8'))
            
            # Extract type and payload
            from .protocol import MessageType
            msg_type = MessageType(message['type'])
            payload = message.get('payload', {})
            
            return msg_type, payload
            
        except asyncio.IncompleteReadError as e:
            logger.error(f"Incomplete read: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            raise
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            raise
