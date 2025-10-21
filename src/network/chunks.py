"""Chunked transfer manager"""

import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ChunkInfo:
    """Chunk information"""
    index: int
    offset: int
    size: int
    hash: str
    received: bool = False


class ChunkedTransferManager:
    """Manages chunked file transfers"""
    
    CHUNK_SIZE = 64 * 1024  # 64KB
    
    def __init__(self, cache_dir: Path = Path("/tmp/pq_sync_chunks")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.active_transfers: Dict[str, Dict] = {}
