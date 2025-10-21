"""Network protocol with versioning"""

import json
import time
from enum import Enum
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

# Protocol version
PROTOCOL_VERSION = "2.0.0"
MIN_COMPATIBLE_VERSION = "2.0.0"


class MessageType(Enum):
    """Protocol message types"""
    # Handshake
    HANDSHAKE_INIT = 1
    HANDSHAKE_RESPONSE = 2
    HANDSHAKE_COMPLETE = 3
    
    # Trust
    IDENTITY_VERIFY = 4
    IDENTITY_CONFIRM = 5
    
    # Key rotation
    KEY_ROTATE = 6
    KEY_ROTATE_ACK = 7
    
    # File operations
    FILE_SYNC_REQUEST = 10
    FILE_SYNC_RESPONSE = 11
    FILE_CHUNK_REQUEST = 12
    FILE_CHUNK_DATA = 13
    FILE_CHUNK_ACK = 14
    FILE_DELETE = 15
    
    # Maintenance
    HEARTBEAT = 20
    ERROR = 21
    PROTOCOL_UPGRADE = 22


@dataclass
class ProtocolMessage:
    """Standard protocol message format"""
    version: str
    msg_type: MessageType
    seq_num: int
    timestamp: float
    payload: Dict[str, Any]
    checksum: Optional[str] = None


class Protocol:
    """Protocol handler with versioning"""
    
    def __init__(self, version: str = PROTOCOL_VERSION):
        self.version = version
        self.sequence_number = 0
        self.peer_version: Optional[str] = None
        self.negotiated_features: set = set()
    
    def negotiate_version(self, peer_version: str, peer_features: list) -> Dict:
        """Negotiate protocol version"""
        self.peer_version = peer_version
        our_features = self._get_supported_features()
        common_features = set(our_features) & set(peer_features)
        self.negotiated_features = common_features
        
        return {
            'version': self.version,
            'features': list(common_features),
            'status': 'compatible'
        }
    
    def _get_supported_features(self) -> list:
        """Get supported protocol features"""
        return [
            'chunked_transfer',
            'deletion_sync',
            'conflict_detection',
            'key_rotation'
        ]
    
    def create_message(self, msg_type: MessageType, payload: Dict) -> ProtocolMessage:
        """Create protocol message"""
        self.sequence_number += 1
        
        return ProtocolMessage(
            version=self.version,
            msg_type=msg_type,
            seq_num=self.sequence_number,
            timestamp=time.time(),
            payload=payload,
            checksum=None
        )
