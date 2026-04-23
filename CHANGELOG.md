# Changelog

## [Unreleased]
- Rootless capture via local VPN interception (#1)
- Screenshot capture alongside API logs (#2)
- iOS support via libimobiledevice (#3)

## [0.1.0] - 2026-04-23
### Added
- ADB-based capture of LLM API traffic from Android devices
- Zero device modification required — developer mode only
- Structured JSONL output with timestamps and session IDs
- Support for emulators and physical devices
- CLI: `android-llm-capture record --device emulator-5554 --output session.jsonl`
- Python API: `AndroidCapture`, `ADBClient`
