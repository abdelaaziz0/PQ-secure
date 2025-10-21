"""File synchronization engine"""

import json
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class FileInfo:
    """File metadata"""
    path: str
    size: int
    hash: str
    modified_time: float
    is_directory: bool = False
    is_deleted: bool = False
    version: int = 1


class SyncEngine:
    """File synchronization engine"""
    
    def __init__(self, sync_dir: Path, identity: str):
        self.sync_dir = Path(sync_dir)
        self.sync_dir.mkdir(parents=True, exist_ok=True)
        self.identity = identity
        
        self.metadata_dir = self.sync_dir / ".pqsync"
        self.metadata_dir.mkdir(exist_ok=True)
        
        self.index_file = self.metadata_dir / "index.json"
        self.file_index: Dict[str, FileInfo] = {}
        
        self.scan_directory()
    
    def scan_directory(self) -> Dict[str, FileInfo]:
        """Scan directory and build index"""
        current_files = {}
        
        for path in self.sync_dir.rglob('*'):
            if '.pqsync' in path.parts:
                continue
            
            if path.is_file():
                rel_path = str(path.relative_to(self.sync_dir))
                current_files[rel_path] = self._get_file_info(path)
        
        self.file_index = current_files
        return self.file_index
    
    def _get_file_info(self, path: Path) -> FileInfo:
        """Get file metadata"""
        stat = path.stat()
        
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return FileInfo(
            path=str(path.relative_to(self.sync_dir)),
            size=stat.st_size,
            hash=hasher.hexdigest(),
            modified_time=stat.st_mtime,
            is_directory=path.is_dir()
        )
    
    def analyze_changes(self, remote_index: Dict[str, FileInfo], 
                       remote_tombstones: Dict = None) -> Dict:
        """Analyze differences"""
        result = {
            'uploads': [],
            'downloads': [],
            'conflicts': [],
            'local_deletions': [],
            'remote_deletions': []
        }
        
        # Files we have that remote doesn't
        for local_path, local_info in self.file_index.items():
            if local_path not in remote_index:
                result['uploads'].append(local_path)
            elif local_info.hash != remote_index[local_path].hash:
                if local_info.modified_time > remote_index[local_path].modified_time:
                    result['uploads'].append(local_path)
                else:
                    result['downloads'].append(local_path)
        
        # Files remote has that we don't
        for remote_path in remote_index:
            if remote_path not in self.file_index:
                result['downloads'].append(remote_path)
        
        return result
