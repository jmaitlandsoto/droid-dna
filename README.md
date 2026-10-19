# READroid

APK malware triage for Claude Code. Cheap static checks run first; Claude investigates only what they cannot clear, using the [REA](https://www.npmjs.com/package/rea-agents) reverse-engineering MCP server. Verdicts are evidence-backed and say "no indicators found", never "safe".

**Status: early development.** `/readroid:scan` works end to end on one platform (Linux x64): fetch or import, static triage, escalation to a team of read-only agents (a planner, parallel investigators and a verdict writer, working from a checklist the server enforces), and a structured verdict. See `READroid Design v2.md` for the plan.

Commands: `/readroid:scan <sha256|path>`, `/readroid:search <text>`.

## Install

```
/plugin install readroid --marketplace <owner>/<repo>
```

(Replace `<owner>/<repo>` with this repository once it is published.)

## Requirements

- Claude Code
- Node.js 18+ (the launcher fetches Node 22 for REA itself if yours is older)
- Network access on first run

Nothing else to install: on first use a launcher downloads a JDK (checksum from Adoptium) and the JADX bridge JAR (pinned SHA-256) into `~/.readroid/tools/`, about 250 MB. The core server has no npm dependencies.

## Optional: the pane (mod)

`readroid-ui/` is a Claude Code mod that adds `/readroid`, a pane with Library and Results tabs (search, Scan, Deep, Ask Claude). It calls the plugin's tools, so install the plugin first. Try it with `claude --plugin-dir ./readroid-ui`.

## Optional: MalwareBazaar key

To fetch known-malware samples, put a free [abuse.ch](https://auth.abuse.ch/) key in `~/.readroid/.env` (see `.env.example`). Keep it outside any repository.

## Safety

- Static analysis only. Nothing is installed or executed.
- The agents can use only read-only Android tools from REA, listed one by one. REA also exposes adb install, Frida and debugger tools, which the agent cannot call.
- Everything inside a sample is treated as data, never as instructions.
- Samples stay in encrypted zips under `~/.readroid/samples/`. This repository never contains samples.

## Layout

```
readroid-ui/             optional pane mod
readroid/                plugin: bin/ launcher, core/ MCP server, lib/, agents/, commands/, skills/
.claude-plugin/          marketplace manifest
READroid Design v2.md    design
ref/                     original design doc
```

## Known issues

- The plugin starts its own REA server (tools named `mcp__plugin_readroid_rea__*`) with the JDK and JADX jar it provisions. If you also have a separate user-level MCP server named `rea` (`mcp__rea__*`), it will not have `REA_JADX_MCP_JAR` and its decompile tools fail with a missing-jar error. Remove it (`claude mcp remove rea`) or set that variable for it. The agents prefer the plugin's tools.
- apktool is not provisioned, so decoded resource XML (for example an accessibility service's config flags) may be unreadable.
- Native payloads are only inspected through `sample_inspect_native` (headers, imports and a sample of strings). Questions that need disassembly end `unresolved` with blocker `no_native_tool`, which lowers the verdict's confidence.
