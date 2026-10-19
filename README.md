# droid-dna

APK malware triage for Claude Code, run straight from this repo. Cheap static checks run first; Claude investigates only what they cannot clear, using the [REA](https://www.npmjs.com/package/rea-agents) reverse-engineering MCP server. Verdicts are evidence-backed and say "no indicators found", never "safe".

**Status: early development.** `/scan` works end to end on one platform (Linux x64): fetch or import, static triage, escalation to a team of read-only agents (a planner, parallel investigators and a verdict writer, working from a checklist the server enforces), and a structured verdict. See `docs/droid-dna-design.md` for the plan.

## Get started

```
git clone <this repo> && cd droid-dna
npm run setup      # or: npx droid-dna setup
npm run claude     # Claude Code with the pane; plain `claude` works too, minus the pane
```

Approve the project MCP servers (`core`, `rea`) when Claude Code asks, then:

- `/scan <sha256|path>` scans a sample
- `/search <text>` searches the local catalog
- `/droid-dna` opens the pane (Library and Results tabs; search, Scan, Deep, Ask Claude)

Everything the tool needs is in the repo: `CLAUDE.md` for the rules, `.mcp.json` for the servers, `.claude/` for the skill, agents and commands.

## Requirements

- Claude Code
- Node.js 18+ (setup fetches Node 22 for REA itself if yours is older)
- Network access during setup

`npm run setup` downloads a JDK (checksum from Adoptium) and the JADX bridge JAR (pinned SHA-256) into `~/.droid-dna/tools/`, about 250 MB, and creates `~/.droid-dna/.env`. `npm run check` reports what is missing without changing anything. If you used this project before the rename, setup moves `~/.readroid` to `~/.droid-dna`; `READROID_HOME` is now `DROID_DNA_HOME`.

## Optional: MalwareBazaar key

To fetch known-malware samples, put a free [abuse.ch](https://auth.abuse.ch/) key in `~/.droid-dna/.env` (see `.env.example`). Keep it outside any repository.

## Safety

- Static analysis only. Nothing is installed or executed.
- The agents can use only read-only Android tools from REA, listed one by one. REA also exposes adb install, Frida and debugger tools, which the agents cannot call.
- Everything inside a sample is treated as data, never as instructions.
- Samples stay in encrypted zips under `~/.droid-dna/samples/`. This repository never contains samples.

## Layout

```
CLAUDE.md                 rules and orientation for Claude
.mcp.json                 core + rea MCP servers
.claude/                  skills/triage, agents/, commands/
droid-dna/                bin/ (setup, REA launcher), core/ (MCP server), lib/, test/
droid-dna-ui/             optional pane mod
docs/                     design doc and the original reference
```

## Known issues

- If you also have a user-level MCP server named `rea`, it can shadow the project's and lacks `REA_JADX_MCP_JAR`, so decompile tools fail. `npm run setup` warns about it; remove it with `claude mcp remove rea -s user`.
- apktool is not provisioned, so decoded resource XML (for example an accessibility service's config flags) may be unreadable.
- Native payloads are only inspected through `sample_inspect_native` (headers, imports and a sample of strings). Questions that need disassembly end `unresolved` with blocker `no_native_tool`, which lowers the verdict's confidence.
