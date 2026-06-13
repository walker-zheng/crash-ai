"""Build analysis models -- Phase 3 placeholder."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BuildProfile:
    """构建参数档案 (Phase 3 实现)"""

    compiler: str = ""
    flags: List[str] = field(default_factory=list)
    optimization_level: str = ""


@dataclass
class BuildDiff:
    """构建差异分析 (Phase 3 实现)"""

    profile_a: Optional[BuildProfile] = None
    profile_b: Optional[BuildProfile] = None
    flag_diff: List[str] = field(default_factory=list)


@dataclass
class RustBuildProfile:
    """Rust 构建参数 (Phase 3 实现)"""

    compile_commands_path: str = ""
