"""全局配置，从环境变量/.env加载。"""
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Config:
    """Crash AI 配置 (frozen, 不可变)"""

    deepseek_api_key: str = field(
        default_factory=lambda: os.getenv("CRASHAI_DEEPSEEK_API_KEY", "")
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("CRASHAI_ANTHROPIC_API_KEY", "")
    )
    default_provider: str = field(
        default_factory=lambda: os.getenv("CRASHAI_DEFAULT_PROVIDER", "deepseek")
    )
    cache_dir: str = field(
        default_factory=lambda: os.path.expanduser(
            os.getenv("CRASHAI_CACHE_DIR", "~/.cache/crash-ai")
        )
    )
    timeout: int = field(
        default_factory=lambda: int(os.getenv("CRASHAI_TIMEOUT", "30"))
    )
