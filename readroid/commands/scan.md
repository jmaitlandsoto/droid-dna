---
description: Scan an APK for malware indicators (cheap static checks first, deep analysis only if needed)
argument-hint: <sha256 | path to .apk>
allowed-tools: mcp__plugin_readroid_core__sample_import, mcp__plugin_readroid_core__sample_fetch, mcp__plugin_readroid_core__sample_open, mcp__plugin_readroid_core__sample_close, mcp__plugin_readroid_core__scan_triage, mcp__plugin_readroid_core__scan_list, mcp__plugin_readroid_core__catalog_search, Agent
---

Scan this APK: $ARGUMENTS

Follow the `triage` skill's procedure exactly. In short:

1. If the argument is a file path, call `sample_import`. If it is a 64-character sha256, call `sample_fetch` (skipped automatically if the file is already on disk).
2. Call `scan_triage`. If `escalate` is false, report its summary and stop.
3. If `escalate` is true, call `sample_open`, spawn the `readroid:apk-analyst` agent with the sha256, the APK path and the tier 1 findings, then call `sample_close` when it finishes.
4. Report the verdict from `scan_list` in plain language: the label, the confidence, the top findings with their evidence, and what was not examined. Say "no indicators found", never "safe".
