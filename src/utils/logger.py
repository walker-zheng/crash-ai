"""统一日志模块。"""
import logging
import sys


def setup_logger(name: str = "crash-ai", level: int = logging.INFO) -> logging.Logger:
    """创建并配置 logger 实例。

    Args:
        name: Logger 名称
        level: 日志级别

    Returns:
        配置好的 Logger 实例
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
