#!/usr/bin/env python3
"""
android_llm_capture.py — standalone single-file entry point.

Adds ``src/`` to sys.path and delegates to the installed package.
Run directly:  python android_llm_capture.py live --tag OkHttp
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the src/ package is importable when running from the project root
# without an editable install.
_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Re-export the full public API so ``import android_llm_capture`` works both
# with and without ``pip install -e .``.
from android_llm_capture import (  # noqa: E402, F401
    AndroidCapture,
    ADBClient,
    CaptureSession,
    CapturedCall,
    LLM_PATTERNS,
    _cli,
    list_devices,
    list_packages,
    main,
    parse_logcat_file,
    parse_logcat_line,
)

# Backwards-compatible alias kept for existing scripts
LLMCapture = AndroidCapture

if __name__ == "__main__":
    sys.exit(main())
