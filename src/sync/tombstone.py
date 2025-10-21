"""
sync/tombstone.py - Deletion Tracking with Tombstones
Addresses critique: implement deletion propagation
"""

import json
import time
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class Tombstone:
    """
    Deletion marker for sync propagation
    Records when and by whom a file was deleted
    """
    path: str
    deleted_time: float
    deleted_by: str  # Identity of deleter
    original_hash: Optional[str] = None
    original_size: Optional[int] = None


class TombstoneManager:
    """
    Manages deletion tombstones for sync
    Ensures deletions propagate correctly across peers
    """
    
    def __init__(self, metadata_dir: Path, identity: str):
        self.metadata_dir = Path(metadata_dir)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.identity = identity
        
        self.tombstone_file = self.metadata_dir / "tombstones.json"
        self.tombstones: Dict[str, Tombstone] = self._load_tombstones()
    
    def _load_tombstones(self) -> Dict[str, Tombstone]:
        """Load tombstones from disk"""
        if not self.tombstone_file.exists():
            return {}
        
        try:
            with open(self.tombstone_file, 'r') as f:
                data = json.load(f)
            return {k: Tombstone(**v) for k, v in data.items()}
        except Exception as e:
            logger.error(f"Failed to load tombstones: {e}")
            return {}
    
    def _save_tombstones(self):
        """Save tombstones to disk"""
        data = {k: asdict(v) for k, v in self.tombstones.items()}
        with open(self.tombstone_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def mark_deleted(self, path: str, file_info: Optional[dict] = None):
        """
        Mark a file as deleted with tombstone
        Preserves original file metadata for conflict resolution
        """
        tombstone = Tombstone(
            path=path,
            deleted_time=time.time(),
            deleted_by=self.identity,
            original_hash=file_info.get('hash') if file_info else None,
            original_size=file_info.get('size') if file_info else None
        )
        
        self.tombstones[path] = tombstone
        self._save_tombstones()
        
        logger.info(f"Created tombstone for {path}")
    
    def is_deleted(self, path: str) -> bool:
        """Check if a file has a deletion tombstone"""
        return path in self.tombstones
    
    def get_tombstone(self, path: str) -> Optional[Tombstone]:
        """Get tombstone for a path"""
        return self.tombstones.get(path)
    
    def should_delete_locally(self, path: str, remote_tomb: Tombstone,
                             local_modified_time: Optional[float]) -> bool:
        """
        Determine if local file should be deleted based on remote tombstone
        Returns True if deletion should be applied
        """
        if local_modified_time is None:
            # File doesn't exist locally
            return False
        
        # Delete only if remote deletion is newer than local modification
        return remote_tomb.deleted_time > local_modified_time
    
    def merge_remote_tombstones(self, remote_tombstones: Dict[str, Tombstone]) -> Dict:
        """
        Merge remote tombstones with local ones
        Returns dict with actions to take
        """
        actions = {
            'delete_local': [],  # Files to delete locally
            'conflicts': []  # Deletions that conflict with local mods
        }
        
        for path, remote_tomb in remote_tombstones.items():
            local_tomb = self.tombstones.get(path)
            
            if local_tomb:
                # Both have deletion - keep newer one
                if remote_tomb.deleted_time > local_tomb.deleted_time:
                    self.tombstones[path] = remote_tomb
            else:
                # New remote deletion
                self.tombstones[path] = remote_tomb
                actions['delete_local'].append(path)
        
        self._save_tombstones()
        return actions
    
    def cleanup_old_tombstones(self, max_age_days: int = 30):
        """
        Remove old tombstones after sync stabilization period
        Keeps tombstone file from growing unbounded
        """
        current_time = time.time()
        max_age_seconds = max_age_days * 24 * 60 * 60
        
        old_tombstones = [
            path for path, tomb in self.tombstones.items()
            if current_time - tomb.deleted_time > max_age_seconds
        ]
        
        for path in old_tombstones:
            del self.tombstones[path]
        
        if old_tombstones:
            self._save_tombstones()
            logger.info(f"Cleaned up {len(old_tombstones)} old tombstones")
        
        return len(old_tombstones)
    
    def get_all_tombstones(self) -> Dict[str, Tombstone]:
        """Get all current tombstones"""
        return self.tombstones.copy()
    
    def remove_tombstone(self, path: str):
        """Remove a tombstone (e.g., after file is recreated)"""
        if path in self.tombstones:
            del self.tombstones[path]
            self._save_tombstones()
            logger.debug(f"Removed tombstone for {path}")
    
    def export_tombstones(self, output_file: Path):
        """Export tombstones for debugging/analysis"""
        with open(output_file, 'w') as f:
            json.dump(
                {k: asdict(v) for k, v in self.tombstones.items()},
                f,
                indent=2
            )
    
    def get_statistics(self) -> dict:
        """Get tombstone statistics"""
        if not self.tombstones:
            return {'count': 0}
        
        ages = [time.time() - t.deleted_time for t in self.tombstones.values()]
        
        return {
            'count': len(self.tombstones),
            'oldest_age_hours': max(ages) / 3600 if ages else 0,
            'newest_age_hours': min(ages) / 3600 if ages else 0,
            'avg_age_hours': (sum(ages) / len(ages)) / 3600 if ages else 0
        }


class DeletionTracker:
    """
    Tracks file deletions by monitoring directory changes
    Works with TombstoneManager to create tombstones
    """
    
    def __init__(self, tombstone_manager: TombstoneManager):
        self.tombstone_manager = tombstone_manager
        self.previous_files: Dict[str, dict] = {}
    
    def snapshot_files(self, current_index: Dict[str, any]):
        """Take snapshot of current file state"""
        self.previous_files = {
            path: {
                'hash': info.hash,
                'size': info.size,
                'mtime': info.modified_time
            }
            for path, info in current_index.items()
            if not info.is_deleted
        }
    
    def detect_deletions(self, current_index: Dict[str, any]) -> list:
        """
        Detect files that were deleted since last snapshot
        Returns list of paths that were deleted
        """
        current_paths = set(
            path for path, info in current_index.items()
            if not info.is_deleted
        )
        previous_paths = set(self.previous_files.keys())
        
        deleted_paths = previous_paths - current_paths
        
        # Create tombstones for deletions
        for path in deleted_paths:
            if not self.tombstone_manager.is_deleted(path):
                file_info = self.previous_files[path]
                self.tombstone_manager.mark_deleted(path, file_info)
        
        return list(deleted_paths)
