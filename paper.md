---
title: 'android-llm-capture: ADB-based screen capture and interaction logging for Android LLM applications'
tags:
  - Python
  - Android
  - LLM
  - capture
  - reproducibility
  - mobile
authors:
  - name: Vaibhav Deshmukh
    orcid: 0000-0001-6745-7062
    affiliation: 1
affiliations:
  - name: Independent Researcher, Nagpur, India
    index: 1
date: 23 April 2026
bibliography: paper.bib
---

# Summary

`android-llm-capture` is a Python tool that uses the Android Debug Bridge (ADB) to capture, log, and replay interactions with large language model (LLM) applications running on Android devices or emulators. Researchers studying mobile LLM deployment, UX evaluation, or accessibility face a gap: there is no standardised method to record complete interaction sessions — including rendered text, taps, and network traffic — from closed Android applications that do not expose APIs. `android-llm-capture` fills this gap by combining screen recording via `adb screenrecord`, UI hierarchy dumps via `uiautomator`, and optional network traffic interception to produce structured session logs that can be replayed and analysed offline.

# Statement of Need

Evaluating LLM-powered Android applications for reproducibility, bias, and safety requires capturing the exact sequence of prompts, responses, and UI states presented to the user [@adadi2018peeking]. Native Android APIs do not permit third-party applications to intercept the content of other apps at the network or UI layer without root access. `android-llm-capture` leverages ADB over USB or TCP/IP — available on any unlocked developer device — to non-intrusively capture sessions from any installed application. The resulting logs enable offline analysis, regression testing across app versions, and construction of interaction datasets for research [@gebru2021datasheets].

# Acknowledgements

The author used Claude (Anthropic) for drafting portions of this manuscript. All scientific claims and design decisions are the author's own.

# References
