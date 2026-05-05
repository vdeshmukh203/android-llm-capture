"""Data models for captured LLM API calls."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class CapturedCall:
    """A single captured LLM API request/response pair.

    Attributes
    ----------
    call_id:
        16-character hex identifier derived from the capture timestamp and URL.
    timestamp:
        Unix epoch timestamp of the moment the call was assembled.
    provider:
        Lower-case provider name (``"openai"``, ``"anthropic"``, …).
    url:
        Full endpoint URL.
    method:
        HTTP method (``"POST"``, ``"GET"``, …).
    request_body:
        Parsed JSON request payload, or ``None`` if unavailable.
    response_status:
        HTTP response status code, or ``None`` if not observed.
    response_body:
        Raw response body string, or ``None`` if not observed.
    source:
        ``"logcat"`` for live captures, ``"file"`` for parsed dumps.
    request_hash:
        SHA-256 of the canonical JSON request body (auto-computed).
    response_hash:
        SHA-256 of the response body string (auto-computed).
    """

    call_id: str
    timestamp: float
    provider: str
    url: str
    method: str
    request_body: Optional[Dict[str, Any]]
    response_status: Optional[int]
    response_body: Optional[str]
    source: str
    request_hash: str = field(init=False)
    response_hash: str = field(init=False)

    def __post_init__(self) -> None:
        req_str = json.dumps(self.request_body, sort_keys=True) if self.request_body else ""
        self.request_hash = _sha256(req_str)
        self.response_hash = _sha256(self.response_body or "")

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary representation."""
        return asdict(self)

    def to_jsonl(self) -> str:
        """Return a single-line JSON string suitable for JSONL output."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapturedCall":
        """Reconstruct a :class:`CapturedCall` from a :meth:`to_dict` snapshot."""
        return cls(
            call_id=d["call_id"],
            timestamp=d["timestamp"],
            provider=d["provider"],
            url=d["url"],
            method=d["method"],
            request_body=d.get("request_body"),
            response_status=d.get("response_status"),
            response_body=d.get("response_body"),
            source=d.get("source", "file"),
        )

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def model(self) -> Optional[str]:
        """Model name from the request body, or ``None``."""
        if self.request_body:
            return self.request_body.get("model")
        return None

    @property
    def prompt_tokens_estimate(self) -> int:
        """Rough estimate of prompt token count (word-count × 4/3)."""
        if not self.request_body:
            return 0
        messages = self.request_body.get("messages", [])
        text = " ".join(
            m.get("content", "") for m in messages if isinstance(m, dict)
        )
        return max(1, len(text.split()) * 4 // 3)
