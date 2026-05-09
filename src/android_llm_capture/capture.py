"""High-level capture interface re-exported from the top-level module."""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running directly from the source tree without installation
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from android_llm_capture import CaptureSession, CapturedCall  # noqa: E402

#: Public alias; mirrors the name advertised in the JOSS paper.
AndroidCapture = CaptureSession

__all__ = ["AndroidCapture", "CaptureSession", "CapturedCall"]
