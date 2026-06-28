from __future__ import annotations

from dataclasses import dataclass

from tools import ToolCall, ToolResult


SENSITIVE_TOOLS = {"send_email"}


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


@dataclass
class GuardConfig:
    require_confirmation_for_sensitive_tools: bool = False
    block_tainted_sensitive_args: bool = False
    user_confirmed_sensitive_action: bool = False


class PolicyGuard:
    def __init__(self, config: GuardConfig) -> None:
        self.config = config

    def inspect(self, call: ToolCall, tainted_fields: set[str]) -> PolicyDecision:
        if call.name not in SENSITIVE_TOOLS:
            return PolicyDecision(True, "non-sensitive tool")

        if (
            self.config.require_confirmation_for_sensitive_tools
            and not self.config.user_confirmed_sensitive_action
        ):
            return PolicyDecision(False, "blocked: sensitive tool requires user confirmation")

        if self.config.block_tainted_sensitive_args and tainted_fields:
            fields = ", ".join(sorted(tainted_fields))
            return PolicyDecision(False, f"blocked: tainted data reached sensitive args ({fields})")

        return PolicyDecision(True, "allowed by policy")


def blocked_result(decision: PolicyDecision) -> ToolResult:
    return ToolResult(False, decision.reason)
