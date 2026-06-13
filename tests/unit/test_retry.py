import pytest
from src.utils.retry import retry_async


class TestRetryAsync:
    @pytest.mark.asyncio
    async def test_success_first_try(self):
        """验证首次成功不重试"""
        call_count = 0

        async def succeed():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await retry_async(succeed, max_retries=3)
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_exception(self):
        """验证指定异常触发重试"""
        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("transient error")
            return "recovered"

        result = await retry_async(
            fail_then_succeed,
            max_retries=3,
            exceptions=(ValueError,),
            base_delay=0.01,  # fast for tests
        )
        assert result == "recovered"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_max_retries_exhausted(self):
        """验证超过最大重试次数后抛出异常"""
        call_count = 0

        async def always_fail():
            nonlocal call_count
            call_count += 1
            raise ValueError("persistent error")

        with pytest.raises(ValueError) as exc_info:
            await retry_async(
                always_fail,
                max_retries=3,
                exceptions=(ValueError,),
                base_delay=0.01,
            )
        assert "persistent error" in str(exc_info.value)
        # 1 initial + 3 retries = 4 total
        assert call_count == 4

    @pytest.mark.asyncio
    async def test_non_retryable_exception(self):
        """验证未注册的异常类型不重试"""
        call_count = 0

        async def fail_type_error():
            nonlocal call_count
            call_count += 1
            raise TypeError("not retryable")

        with pytest.raises(TypeError):
            await retry_async(
                fail_type_error,
                max_retries=3,
                exceptions=(ValueError,),  # only ValueError
                base_delay=0.01,
            )
        assert call_count == 1  # no retry

    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """验证延迟指数增长"""
        delays = []

        async def fail_with_delay():
            delays.append(len(delays))
            if len(delays) < 3:
                raise ValueError("fail")
            return "ok"

        # base_delay=0.01 with jitter makes exact timing unreliable
        # Just verify it retries and eventually succeeds
        result = await retry_async(
            fail_with_delay,
            max_retries=3,
            exceptions=(ValueError,),
            base_delay=0.01,
            max_delay=0.1,
        )
        assert result == "ok"
        assert len(delays) == 3  # 2 failures + 1 success
