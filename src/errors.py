"""Crash AI 异常层级 — 对应 5 种退出码。"""


class CrashAIError(Exception):
    """Base exception for crash-ai."""
    exit_code = 5


class InputError(CrashAIError):
    """格式不支持/文件损坏 → exit code 2"""
    exit_code = 2


class ConfigError(CrashAIError):
    """配置错误 → exit code 3"""
    exit_code = 3


class NetworkError(CrashAIError):
    """网络/API 错误 → exit code 4"""
    exit_code = 4


class AnalysisIncompleteError(CrashAIError):
    """分析不完整 → exit code 1"""
    exit_code = 1
