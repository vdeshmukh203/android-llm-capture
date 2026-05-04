"""Data model for a captured LLM API call."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class CapturedCall:
    """A single captured LLM API request/response pair."""

    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str  # "logcat" | "file"
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self) -> None:
        req_str = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        self.request_hash = _sha256(req_str)
        self.response_hash = _sha256(self.response_body or "")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def model(self) -> Optional[str]:
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """Rough token count estimate based on whitespace-split word count."""
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "") for m in messages if isinstance(m, dict)
        )
        return max(1, len(text.split()) * 4 // 3)
