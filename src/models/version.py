"""Version diff models -- Phase 2 placeholder."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class VersionDiff:
    """版本差分结果 (Phase 2 实现)"""

    commit_a: str = ""
    commit_b: str = ""
    changed_files: List[str] = field(default_factory=list)
    diff_summary: str = ""


@dataclass
class BranchScanResult:
    """分支横展结果 (Phase 2 实现)"""

    branch: str = ""
    affected_commits: List[str] = field(default_factory=list)
    common_root_cause: Optional[str] = None
