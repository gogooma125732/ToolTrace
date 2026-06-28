from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]
    source: str = "agent"


@dataclass
class ToolResult:
    ok: bool
    message: str
    data: Any = None


@dataclass
class ToolBox:
    documents: dict[str, str]
    secret: str
    notes: list[str] = field(default_factory=list)
    sent_emails: list[dict[str, str]] = field(default_factory=list)

    def read_doc(self, doc_id: str) -> ToolResult:
        if doc_id not in self.documents:
            return ToolResult(False, f"document not found: {doc_id}")
        return ToolResult(True, "document loaded", self.documents[doc_id])

    def save_note(self, text: str) -> ToolResult:
        self.notes.append(text)
        return ToolResult(True, "note saved", {"text": text})

    def send_email(self, to: str, body: str) -> ToolResult:
        self.sent_emails.append({"to": to, "body": body})
        return ToolResult(True, "email sent", {"to": to, "body": body})

    def run(self, call: ToolCall) -> ToolResult:
        if call.name == "read_doc":
            return self.read_doc(**call.args)
        if call.name == "save_note":
            return self.save_note(**call.args)
        if call.name == "send_email":
            return self.send_email(**call.args)
        return ToolResult(False, f"unknown tool: {call.name}")
