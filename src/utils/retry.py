"""LLM 重试 + 指数退避工具。"""
import asyncio
import random
from typing import TypeVar, Callable, Awaitable, Tuple, Type

T = TypeVar("T")


async def retry_async(
    fn: Callable[..., Awaitable[T]],
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    **kwargs
) -> T:
    """异步重试，带指数退避 + jitter。

    Args:
        fn: 异步可调用对象
        max_retries: 最大重试次数
        base_delay: 基础延迟 (秒)
        max_delay: 最大延迟上限 (秒)
        exceptions: 可重试的异常类型元组

    Returns:
        fn 的成功返回值

    Raises:
        最后一次尝试的异常 (所有重试耗尽后)
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except exceptions as e:
            last_exception = e
            if attempt == max_retries:
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            jitter = random.uniform(0, delay * 0.1)
            await asyncio.sleep(delay + jitter)


__all__ = ["retry_async"]
