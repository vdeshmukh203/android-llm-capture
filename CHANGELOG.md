# Changelog

## [Unreleased]
- Rootless capture via local VPN interception (#1)
- Screenshot capture alongside API logs (#2)
- iOS support via libimobiledevice (#3)

## [0.2.0] - 2026-05-09
### Added
- **GUI** — four-tab tkinter interface (`android-llm-capture gui`): Live Capture,
  Parse File, Call Viewer, Stats
- `compute_stats()` public helper function
- `load_jsonl()` public helper function
- `DELETE` HTTP method support in OkHttp parser
- `gui` subcommand in CLI

### Fixed
- Parser state now correctly cleared by `<-- END HTTP` marker; responses without
  a JSON body no longer leave state stuck
- `<-- END POST` / `--> END METHOD` markers drive phase transitions so body
  accumulation is scoped to the correct phase
- `list_devices()` and `list_packages()` no longer import `subprocess` redundantly
  (already a module-level import)
- `_cli` entry-point alias wired up so `pip install` + `android-llm-capture`
  invocation works correctly
- `src/android_llm_capture/__init__.py` broken imports resolved; `capture.py`
  and `adb.py` submodules created
- `prompt_tokens_estimate` skips non-string message content (vision API payloads)

### Changed
- Body lines filtered to those starting with `{` or `[` (JSON), preventing
  spurious accumulation of unrelated log lines
- Replay command reuses `load_jsonl()` instead of inline parsing
- Stats command reuses `compute_stats()` instead of inline logic

## [0.1.0] - 2026-04-23
### Added
- ADB-based capture of LLM API traffic from Android devices
- Zero device modification required — developer mode only
- Structured JSONL output with timestamps and session IDs
- Support for emulators and physical devices
- CLI subcommands: `live`, `file`, `replay`, `stats`
- Python API: `CaptureSession`, `CapturedCall`, `parse_logcat_file`
