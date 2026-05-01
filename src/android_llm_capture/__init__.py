"""
android_llm_capture — ADB-based Android LLM interaction capture tool.

Re-exports the public API from the top-level module so the package can be
imported either as ``import android_llm_capture`` (root module) or installed
as a proper package via ``pip install .``.
"""

from android_llm_capture import (  # noqa: F401  (re-export)
    __version__,
    __author__,
    __license__,
    __all__,
    CapturedCall,
    CaptureSession,
    LLMCapture,
    LLM_PATTERNS,
    parse_logcat_line,
    parse_logcat_file,
    load_jsonl,
    list_devices,
    list_packages,
    main,
)
