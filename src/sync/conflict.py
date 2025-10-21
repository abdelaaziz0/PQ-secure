import time
import shutil
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ConflictType(Enum):
    """Types of sync conflicts"""
    CONCURRENT_MODIFY = "concurrent_modify"  # Both sides modified
    DELETE_MODIFY = "delete_modify"  # One deleted, other modified
    CREATE_CREATE = "create_create"  # Both created different files


class ResolutionStrategy(Enum):
    """Conflict resolution strategies"""
    KEEP_LOCAL = "local"
    KEEP_REMOTE = "remote"
    KEEP_BOTH = "both"
    KEEP_NEWER = "newer"
    MANUAL = "manual"


@dataclass
class Conflict:
    """Represents a sync conflict"""
    path: str
    conflict_type: ConflictType
    local_info: Optional[dict]
    remote_info: Optional[dict]
    detected_at: float
    resolved: bool = False
    resolution: Optional[ResolutionStrategy] = None


class ConflictResolver:
    """
    Handles conflict detection and resolution
    Separates conflict logic from sync engine
    """
    
    def __init__(self, sync_dir: Path, conflicts_dir: Path):
        self.sync_dir = Path(sync_dir)
        self.conflicts_dir = Path(conflicts_dir)
        self.conflicts_dir.mkdir(parents=True, exist_ok=True)
        
        self.active_conflicts: List[Conflict] = []
    
    def detect_conflicts(self, local_index: dict, remote_index: dict,
                        local_tombstones: dict, remote_tombstones: dict) -> List[Conflict]:
        """
        Detect all types of conflicts between local and remote
        Returns list of Conflict objects
        """
        conflicts = []
        current_time = time.time()
        
        # Check for concurrent modifications
        for path in set(local_index.keys()) & set(remote_index.keys()):
            local = local_index[path]
            remote = remote_index[path]
            
            if local.hash != remote.hash:
                # Files differ - check if concurrent modification
                time_diff = abs(local.modified_time - remote.modified_time)
                
                if time_diff < 2.0:  # Modified within 2 seconds
                    conflicts.append(Conflict(
                        path=path,
                        conflict_type=ConflictType.CONCURRENT_MODIFY,
                        local_info={'hash': local.hash, 'mtime': local.modified_time},
                        remote_info={'hash': remote.hash, 'mtime': remote.modified_time},
                        detected_at=current_time
                    ))
        
        # Check for delete-modify conflicts
        for path in local_tombstones:
            if path in remote_index and not remote_index[path].is_deleted:
                tomb = local_tombstones[path]
                remote = remote_index[path]
                
                if remote.modified_time > tomb.deleted_time:
                    conflicts.append(Conflict(
                        path=path,
                        conflict_type=ConflictType.DELETE_MODIFY,
                        local_info={'deleted_at': tomb.deleted_time},
                        remote_info={'hash': remote.hash, 'mtime': remote.modified_time},
                        detected_at=current_time
                    ))
        
        for path in remote_tombstones:
            if path in local_index and not local_index[path].is_deleted:
                tomb = remote_tombstones[path]
                local = local_index[path]
                
                if local.modified_time > tomb.deleted_time:
                    conflicts.append(Conflict(
                        path=path,
                        conflict_type=ConflictType.DELETE_MODIFY,
                        local_info={'hash': local.hash, 'mtime': local.modified_time},
                        remote_info={'deleted_at': tomb.deleted_time},
                        detected_at=current_time
                    ))
        
        self.active_conflicts.extend(conflicts)
        
        if conflicts:
            logger.warning(f"Detected {len(conflicts)} conflicts")
            for c in conflicts:
                logger.warning(f"  {c.conflict_type.value}: {c.path}")
        
        return conflicts
    
    def resolve_conflict(self, conflict: Conflict, 
                        strategy: ResolutionStrategy) -> bool:
        """
        Resolve a conflict using specified strategy
        Returns True if resolution successful
        """
        try:
            if strategy == ResolutionStrategy.KEEP_BOTH:
                self._resolve_keep_both(conflict)
            elif strategy == ResolutionStrategy.KEEP_LOCAL:
                self._resolve_keep_local(conflict)
            elif strategy == ResolutionStrategy.KEEP_REMOTE:
                self._resolve_keep_remote(conflict)
            elif strategy == ResolutionStrategy.KEEP_NEWER:
                self._resolve_keep_newer(conflict)
            elif strategy == ResolutionStrategy.MANUAL:
                self._prepare_manual_resolution(conflict)
            
            conflict.resolved = True
            conflict.resolution = strategy
            
            logger.info(f"Resolved conflict {conflict.path} with {strategy.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to resolve conflict {conflict.path}: {e}")
            return False
    
    def _resolve_keep_both(self, conflict: Conflict):
        """
        Keep both versions by renaming one
        This is the safest strategy - no data loss
        """
        local_path = self.sync_dir / conflict.path
        
        if not local_path.exists():
            return
        
        # Create conflict copy with timestamp
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        stem = local_path.stem
        suffix = local_path.suffix
        
        conflict_name = f"{stem}_conflict_{timestamp}{suffix}"
        conflict_path = local_path.parent / conflict_name
        
        # Copy local version
        shutil.copy2(local_path, conflict_path)
        
        logger.info(f"Saved conflict copy: {conflict_path.name}")
        
        # Remote version will be downloaded to original path
    
    def _resolve_keep_local(self, conflict: Conflict):
        """Keep local version, discard remote"""
        # Simply increment local version number
        # Sync engine will upload this as newer version
        pass
    
    def _resolve_keep_remote(self, conflict: Conflict):
        """Keep remote version, discard local"""
        # Delete local file if exists
        local_path = self.sync_dir / conflict.path
        if local_path.exists():
            local_path.unlink()
        
        # Sync engine will download remote version
    
    def _resolve_keep_newer(self, conflict: Conflict):
        """Keep whichever version is newer"""
        if not conflict.local_info or not conflict.remote_info:
            # Can't compare times for delete-modify conflict
            self._resolve_keep_both(conflict)
            return
        
        local_time = conflict.local_info.get('mtime', 0)
        remote_time = conflict.remote_info.get('mtime', 0)
        
        if local_time > remote_time:
            self._resolve_keep_local(conflict)
        else:
            self._resolve_keep_remote(conflict)
    
    def _prepare_manual_resolution(self, conflict: Conflict):
        """
        Prepare conflict for manual resolution
        Save both versions side-by-side
        """
        conflict_dir = self.conflicts_dir / conflict.path
        conflict_dir.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy local version
        local_path = self.sync_dir / conflict.path
        if local_path.exists():
            local_copy = conflict_dir.parent / f"{local_path.stem}_LOCAL{local_path.suffix}"
            shutil.copy2(local_path, local_copy)
        
        # Remote version will be saved as _REMOTE when downloaded
        
        logger.info(f"Prepared manual resolution for {conflict.path}")
        logger.info(f"Merge files in: {conflict_dir.parent}")
    
    def auto_resolve_conflicts(self, conflicts: List[Conflict],
                              default_strategy: ResolutionStrategy = ResolutionStrategy.KEEP_BOTH):
        """
        Automatically resolve conflicts using default strategy
        KEEP_BOTH is safest - preserves all data
        """
        for conflict in conflicts:
            if not conflict.resolved:
                self.resolve_conflict(conflict, default_strategy)
    
    def get_active_conflicts(self) -> List[Conflict]:
        """Get list of unresolved conflicts"""
        return [c for c in self.active_conflicts if not c.resolved]
    
    def clear_resolved_conflicts(self):
        """Clear resolved conflicts from tracking"""
        self.active_conflicts = [c for c in self.active_conflicts if not c.resolved]
