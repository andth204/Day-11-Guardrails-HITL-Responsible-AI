"""
Assignment 11 — Audit Log + Monitoring & Alerts

Why this layer is needed:
  Input/Output guardrails act *synchronously* — they block or pass.
  Neither keeps a historical record.  Audit logging provides:
    1. Compliance evidence  (who sent what, when, and what was blocked)
    2. Post-incident forensics  (trace back how an attack unfolded)
    3. Metrics for monitoring  (is the block rate unusually high/low?)

  MonitoringAlert reads the AuditLogPlugin's metrics and fires alerts
  when thresholds are exceeded — e.g., a coordinated attack campaign
  or a broken filter that lets everything through.
"""
import json
import time
from datetime import datetime

from google.adk.plugins import base_plugin
from google.genai import types


class AuditLogPlugin(base_plugin.BasePlugin):
    """Records every interaction: input, output, which layer blocked, latency.

    Never blocks — purely observational.  Export to JSON with export_json().
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs: list[dict] = []
        # Temporary store while waiting for the after_model callback.
        # Key: a stable string derived from the invocation context.
        self._pending: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ctx_key(self, invocation_context) -> str:
        """Build a stable key from invocation context (session id or index)."""
        try:
            return invocation_context.session.id
        except AttributeError:
            pass
        try:
            return str(invocation_context.session_id)
        except AttributeError:
            return str(len(self.logs))

    def _text_from_content(self, content: types.Content) -> str:
        text = ""
        if content and content.parts:
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    def _text_from_response(self, llm_response) -> str:
        text = ""
        try:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        except AttributeError:
            pass
        return text

    @staticmethod
    def _blocked_by(response_text: str) -> str | None:
        """Guess which layer produced the block message, if any."""
        if "[RATE LIMITED]" in response_text:
            return "RateLimiter"
        if "[BLOCKED]" in response_text:
            lower = response_text.lower()
            if "injection" in lower or "prompt" in lower:
                return "InputGuardrail (injection)"
            if "off-topic" in lower or "banking" in lower:
                return "InputGuardrail (topic)"
            if "safety" in lower or "standard" in lower:
                return "OutputGuardrail (judge)"
            return "InputGuardrail"
        return None

    # ------------------------------------------------------------------
    # ADK callbacks
    # ------------------------------------------------------------------

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message: types.Content,
    ) -> None:
        """Capture input + start timer.  Never blocks."""
        key = self._ctx_key(invocation_context)
        self._pending[key] = {
            "id": len(self.logs) + len(self._pending) + 1,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_input": self._text_from_content(user_message),
            "output": None,
            "blocked": False,
            "blocked_by": None,
            "latency_ms": None,
            "_t0": time.monotonic(),
        }
        return None

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Capture output + latency, then move entry to permanent log.  Never modifies response."""
        # Resolve the pending key
        try:
            key = callback_context.invocation_context.session.id
        except AttributeError:
            key = list(self._pending.keys())[-1] if self._pending else None

        entry = self._pending.pop(key, None)
        if entry is None:
            # Fallback: create a minimal entry
            entry = {
                "id": len(self.logs) + 1,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "user_input": "",
                "_t0": time.monotonic(),
            }

        output_text = self._text_from_response(llm_response)
        blocked_by = self._blocked_by(output_text)

        entry["output"] = output_text[:500]   # truncate for storage
        entry["blocked"] = blocked_by is not None
        entry["blocked_by"] = blocked_by
        entry["latency_ms"] = round(
            (time.monotonic() - entry.pop("_t0", time.monotonic())) * 1000, 1
        )

        self.logs.append(entry)
        return llm_response   # pass through unchanged

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_json(self, filepath: str = "audit_log.json") -> None:
        """Write all log entries to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, default=str, ensure_ascii=False)
        print(f"[AuditLog] Exported {len(self.logs)} entries → {filepath}")

    def get_stats(self) -> dict:
        """Return summary statistics for the monitoring dashboard."""
        total = len(self.logs)
        blocked = sum(1 for e in self.logs if e["blocked"])
        avg_latency = (
            sum(e["latency_ms"] for e in self.logs if e["latency_ms"])
            / total if total > 0 else 0.0
        )
        by_layer: dict[str, int] = {}
        for e in self.logs:
            if e["blocked_by"]:
                by_layer[e["blocked_by"]] = by_layer.get(e["blocked_by"], 0) + 1

        return {
            "total": total,
            "blocked": blocked,
            "passed": total - blocked,
            "block_rate": blocked / total if total > 0 else 0.0,
            "avg_latency_ms": round(avg_latency, 1),
            "blocked_by_layer": by_layer,
        }


class MonitoringAlert:
    """Reads AuditLogPlugin metrics and fires alerts when thresholds exceeded.

    Alerts cover:
      - Block rate too HIGH  → possible coordinated attack campaign
      - Block rate too LOW   → filters might be disabled or bypassed
      - Rate-limiter hits    → possible brute-force attempt
    """

    def __init__(
        self,
        audit_plugin: AuditLogPlugin,
        max_block_rate: float = 0.50,
        min_block_rate: float = 0.01,
        rate_limit_plugins: list | None = None,
    ):
        self.audit = audit_plugin
        self.max_block_rate = max_block_rate
        self.min_block_rate = min_block_rate
        self.rate_limit_plugins = rate_limit_plugins or []
        self.alerts: list[str] = []

    def check_metrics(self) -> list[str]:
        """Evaluate all metrics and print the monitoring dashboard.

        Returns:
            List of alert strings that fired.
        """
        self.alerts = []
        stats = self.audit.get_stats()

        print("\n" + "=" * 60)
        print("MONITORING DASHBOARD")
        print("=" * 60)
        print(f"  Total requests  : {stats['total']}")
        print(f"  Blocked         : {stats['blocked']} ({stats['block_rate']:.1%})")
        print(f"  Passed          : {stats['passed']}")
        print(f"  Avg latency     : {stats['avg_latency_ms']} ms")
        if stats["blocked_by_layer"]:
            print("  Blocks by layer :")
            for layer, count in stats["blocked_by_layer"].items():
                print(f"    {layer:<35} {count}")

        if stats["total"] == 0:
            print("\n  No interactions recorded yet.")
            print("=" * 60)
            return []

        # Alert: block rate too high
        if stats["block_rate"] > self.max_block_rate:
            alert = (
                f"[ALERT] Block rate {stats['block_rate']:.1%} "
                f"> {self.max_block_rate:.1%} — possible coordinated attack!"
            )
            self.alerts.append(alert)
            print(f"\n  {alert}")

        # Alert: block rate suspiciously low (only meaningful after ≥10 requests)
        if stats["total"] >= 10 and stats["block_rate"] < self.min_block_rate:
            alert = (
                f"[ALERT] Block rate {stats['block_rate']:.1%} "
                f"< {self.min_block_rate:.1%} — filters may be bypassed!"
            )
            self.alerts.append(alert)
            print(f"\n  {alert}")

        # Rate-limiter stats
        for rl in self.rate_limit_plugins:
            rl_blocked = getattr(rl, "blocked_count", 0)
            rl_total = getattr(rl, "total_count", 0)
            print(f"\n  Rate limiter    : {rl_blocked}/{rl_total} requests blocked")
            if rl_blocked >= 5:
                alert = (
                    f"[ALERT] {rl_blocked} rate-limited requests "
                    "— possible brute-force attempt!"
                )
                self.alerts.append(alert)
                print(f"  {alert}")

        if not self.alerts:
            print("\n  All metrics within normal thresholds. ✓")

        print("=" * 60)
        return self.alerts
