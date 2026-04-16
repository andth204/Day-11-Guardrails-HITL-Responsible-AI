"""
Assignment 11 — Rate Limiter (Sliding Window, Per-User)

Why this layer is needed:
  Other layers (injection detection, topic filter) inspect *content*.
  None of them detect *request frequency* abuse.
  A rate limiter is the only layer that catches brute-force and
  DoS-style attacks by limiting how many requests a single user
  can send in a rolling time window.
"""
import time
from collections import defaultdict, deque

from google.adk.agents.invocation_context import InvocationContext
from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Sliding-window rate limiter — blocks users who exceed the request limit.

    Algorithm:
      - Maintain a deque of timestamps per user_id.
      - On each request, drop timestamps older than `window_seconds`.
      - If the remaining count >= max_requests, block the request.
      - Otherwise, record the new timestamp and pass through.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Maps user_id -> deque of request timestamps (float)
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check rate limit before passing message to the LLM.

        Returns:
            types.Content block message if rate-limited, else None (pass through).
        """
        # Determine user identity
        user_id = (
            getattr(invocation_context, "user_id", None) or "anonymous"
        )
        now = time.time()
        window = self.user_windows[user_id]

        # Evict timestamps outside the current window
        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        self.total_count += 1

        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait_secs = int(window[0] + self.window_seconds - now) + 1
            return types.Content(
                role="model",
                parts=[
                    types.Part.from_text(
                        text=(
                            f"[RATE LIMITED] You have sent {len(window)} requests "
                            f"in the last {self.window_seconds}s "
                            f"(limit: {self.max_requests}). "
                            f"Please wait {wait_secs} seconds and try again."
                        )
                    )
                ],
            )

        # Record this request and allow it through
        window.append(now)
        return None


# ============================================================
# Quick test
# ============================================================

async def test_rate_limiter():
    """Send 15 rapid requests from the same user; first 10 pass, last 5 blocked."""
    import asyncio

    plugin = RateLimitPlugin(max_requests=10, window_seconds=60)

    print("Testing RateLimitPlugin (10 req / 60 s):")
    for i in range(1, 16):
        dummy_content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=f"Request #{i}")],
        )

        class _FakeCtx:
            user_id = "test_user"

        result = await plugin.on_user_message_callback(
            invocation_context=_FakeCtx(),
            user_message=dummy_content,
        )
        status = "BLOCKED" if result else "PASS"
        print(f"  Request {i:>2}: {status}")

    print(
        f"\nStats: {plugin.blocked_count} blocked / {plugin.total_count} total"
    )


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_rate_limiter())
