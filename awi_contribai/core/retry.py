"""Small async retry helper."""

from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable

logger = logging.getLogger(__name__)


def async_retry(max_retries: int = 3, base_delay: float = 1.0):
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    if attempt >= max_retries:
                        break
                    delay = base_delay * (2**attempt)
                    logger.warning("Retry %s after %.1fs: %s", func.__name__, delay, exc)
                    await asyncio.sleep(delay)
            raise last_exc

        return wrapper

    return decorator
