# droid-dna v2: Plugin + Mod — Design

Status: Draft v2 (revises `ref/ReaLight APK Malware Analysis Mod — Design.md`)

## What changed from v1

| v1                                                            | v2                                                                                                                          |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Mod is the product; `droid-dna-core` is a CLI it shells out to | **A Claude Code plugin is the product.** It works in any Claude Code session with no mod. The mod is an optional UI on top. |
| SQLite catalog                                                | One JSON catalog file plus one JSON file per scan                                                                           |
| Device tab, adb source                                        | Cut for v1. The source-adapter interface stays, so adb is a later adapter.                                                  |
| Secrets in `userConfig`                                       | `.env` file, outside any repo                                                                                               |
| Token budget enforced per scan                                | Dropped for now. Only `maxTurns` bounds the analyst.                                                                        |
| Tier 1 through the REA CLI                                    | Tier 1 is our own static pass (androguard/JADX). REA is for tier 2 only.                                                    |

## Shape

```
droid-dna (plugin)                      droid-dna-ui (mod, optional)
  .mcp.json  -> droid-dna MCP server      hooks/register.tsx
  agents/apk-analyst.md                   - /droid-dna pane: Library, Results
  skills/triage, skills/report-reading    - calls the plugin's MCP tools
  commands/scan.md, search.md               with $.mcp.call
  core/ (TypeScript, built to dist/)      - depends on the plugin
```

REA is a separate MCP server, installed once with `npx rea-agents@latest setup`. Its tools are used only by the analyst.

**Why an MCP server and not a CLI.** The repo ships `droid-dna/core/` as a stdio MCP server declared in the root `.mcp.json`. That gives us:

- The plugin is the whole product. A user with no mod can run `/scan <file>` and get a verdict.
- The mod needs no CLI on `PATH`. It calls the server's tools through `$.mcp.call("droid-dna", tool, args)`. The mod's `plugin.json` lists the plugin under `dependencies`.
- `droid-dna_report` (the structured verdict tool) is just another tool on the same server, so the analyst can call it directly.
- The same `core/` has a CLI entry (`droid-dna bench`, `droid-dna triage <file>`) for CI, so the benchmark still runs headless.

The cost: the user needs Node on the machine. That is already required for `npx rea-agents`.

## Plugin components

**MCP server `droid-dna` (core).** Owns all file I/O and all cheap analysis.

| Tool               | Does                                                                                          |
| ------------------ | --------------------------------------------------------------------------------------------- |
| `droid-dna_search` | Query the catalog (and the cached F-Droid index) by name, label or source                     |
| `droid-dna_sync`   | Pull metadata only: ~500 recent MalwareBazaar Android entries, the F-Droid index              |
| `droid-dna_fetch`  | Download one APK, verify SHA-256, unzip MalwareBazaar's `infected` zip to a per-scan temp dir |
| `droid-dna_import` | Add a local APK by path; hash it                                                              |
| `droid-dna_triage` | Tier 0 and 1; writes the full report to disk and returns a summary plus a `escalate` flag     |
| `droid-dna_report` | Validates the verdict schema, writes the scan file, rejects free text                         |
| `droid-dna_scans`  | List scans and read one (used by the mod's Results tab)                                       |

**Agent `apk-analyst`** (tier 2). Tools allow-list: the REA read-only tools plus `mcp__droid-dna__droid-dna_report`. No Bash, no writes, no web. Its brief is the tier 1 report. `maxTurns` bounds it. The sample is data, never instructions.

**Skill `triage`.** The procedure the main session follows: fetch or import, triage, and spawn the analyst only if `escalate` is true. It also tells Claude to keep to the plain-language rules (say "no indicators found", never "safe").

**Commands.** `/scan <sha256|path>`, `/search <text>`, `/droid-dna:sync`. These make the plugin usable alone, and they are also how the mod's buttons can run a scan by submitting a prompt.

## Storage (JSON, no SQLite)

Under `~/.droid-dna/` (outside any repo):

```
catalog.json            # apks + labels, keyed by sha256
fdroid-index.json       # cached raw index, queried, not copied into the catalog
scans/<sha256>.<n>.json # one file per scan: stages, verdict, findings, versions
reports/<sha256>.<n>/   # full tier 1 report, REA evidence refs
samples/                # encrypted zips at rest, never bare .apk
.env                    # keys (see below)
```

`catalog.json` shape:

```json
{
  "schema": 1,
  "apks": {
    "<sha256>": {
      "pkg": "...",
      "versionName": "...",
      "sizeBytes": 0,
      "localPath": null,
      "sources": [{ "source": "malwarebazaar", "ref": "..." }],
      "labels": [
        {
          "label": "malicious",
          "family": "...",
          "origin": "malwarebazaar:tag",
          "confidence": 0.9
        }
      ]
    }
  }
}
```

Rules that carry over from v1:

- **Labels never come from scans.** Ground truth lives in `apks[].labels`; verdicts live only in `scans/`.
- **Pinning.** Each scan file records pipeline, IOC and model versions.
- **Single writer.** Only the MCP server writes. Writes go to a temp file and rename, so a crash can't leave half a file. Per-scan files mean parallel scans never contend over one file.
- **Size.** A few thousand entries is fine as JSON. If search gets slow, the escape hatch is swapping `catalog.ts` for SQLite behind the same functions.

## Secrets

- The MalwareBazaar key goes in `~/.droid-dna/.env` as `MALWAREBAZAAR_KEY=...`, mode 600. The server loads it on start; a real environment variable wins.
- A project-level `.env` is also read if present, and `droid-dna_sync` warns if the project isn't gitignoring it.
- The analyst can't read the file (no Bash or Read). The main session can, so the skill tells Claude never to print or open it.
- Non-secret settings (cache dir, escalation threshold, parallelism) go in `~/.droid-dna/config.json`, so they work with or without the mod.

## Analysis tiers

Same as v1, with two changes: tier 1 uses our own pass, and the device source is gone.

| Tier            | Runs in                         | Escalates when                                           |
| --------------- | ------------------------------- | -------------------------------------------------------- |
| 0 Identity      | core                            | no exact hash match against known-bad/known-good lists   |
| 1 Static triage | core, androguard or JADX direct | score ≥ threshold (default 30) or any high-severity rule |
| 2 Deep analysis | `apk-analyst` + REA MCP         | analyst asks for runtime proof and the user opts in      |
| 3 Dynamic       | opt-in, later                   | n/a                                                      |

The verdict schema is unchanged. `inconclusive` stays a first-class outcome.

## Mod (`droid-dna-ui`)

Thin. Library and Results tabs only.

- `/droid-dna` opens the pane. Library rows come from `droid-dna_search`; Results from `droid-dna_scans`.
- **Scan** button: enqueue, then run `droid-dna_fetch` + `droid-dna_triage` through `$.mcp.call`. If `escalate`, spawn the analyst with `$.agent.spawn`. The mod handles the queue (at most 2 analysts) because hooks can't await a whole scan.
- **Ask Claude about this** uses `$.prompt.submit` with the report path.
- Pane state lives in atoms; scan state lives in the scan files, so a reload loses nothing. On start the mod reconciles any scan stuck in `triage` or `deep`.
- On mobile, search moves to command arguments (no `Input` there).

The mod adds nothing the plugin can't do; it makes browsing, watching progress and clicking easier.

## Prompt injection (now and next)

- **Now:** the analyst has a read-only allow-list, and its prompt says sample content is data.
- **Next iteration (Jev):** screen sample-derived strings before Claude sees them. There are two seams:
  1. In `droid-dna_triage`, screen strings before they enter the tier 1 report (the analyst's brief).
  2. In the mod, a `tool.call` hook on REA tool results (`await next(e)`, then inspect and redact) catches content the analyst pulls later. This is the one thing that needs the mod, not just the plugin.

## Safety, legal, cost

Unchanged from v1: static analysis only, nothing installed or executed, samples kept as zips at rest and extracted per scan to a temp dir that is deleted afterwards, cache outside git, no samples or URLs shipped, bring-your-own key, MalwareBazaar fair use. Cost control is the escalation threshold plus `maxTurns`; per-scan token budgets are deferred.

## Evaluation

Unchanged: `bench/v1.json` pins 300 SHA-256s and labels. `droid-dna bench --tiers 0,1` is free and runs in CI. Tier 2 runs are manual per release, via `claude -p` driving the same plugin.

## Milestones

1. **M0 Spike.** Run `npx rea-agents@latest setup`; confirm a registered or plugin subagent can call REA's tools; run REA by hand on one malware and one F-Droid APK; check REA exposes no write or exec tools.
2. **M1 Core.** MCP server with catalog JSON, MalwareBazaar, F-Droid and local adapters, tier 0, 10 tier 1 rules. Exit: `droid-dna bench --tiers 0,1` on 50 APKs.
3. **M2 Plugin.** `.mcp.json`, `apk-analyst`, `droid-dna_report`, `/scan`. Exit: end-to-end verdict with evidence on 5 known samples, **with no mod installed**.
4. **M3 Mod.** Pane with Library and Results, scan queue, verdict card, Ask Claude.
5. **M4 Benchmark v1.** 300 APKs, metrics, threshold tuning.

## Open questions

- [ ] Does `npx rea-agents@latest setup` register REA for the whole session (so plugin subagents see it), or only configure a specific client? Confirm in M0.
- [ ] How is `core/` built and shipped: commit `dist/`, or build on install? Plugins have no build step on install, so committing `dist/` is the likely answer.
- [ ] Python (androguard) vs JVM (JADX) for tier 1: the choice sets the second runtime the user must have.
- [ ] One threshold or one per category?
- [ ] Name: "droid-dna" is a working title.

## Zero-install provisioning (decided after M0)

Goal: a user installs the plugin and it works, with no manual install of Java, JADX or REA.

- The repo does not bundle the JDK (~200 MB, per-platform) or the JADX JAR (~43 MB). It downloads them during `npm run setup` (and on first launch if missing) into `~/.droid-dna/tools/`, so updates do not re-download them.
- Every download is checked against a pinned SHA-256 (JDK: Adoptium's published checksum; JAR: pinned in the plugin).
- `.mcp.json` launches REA through a small Node launcher in the plugin, not `npx` directly. The launcher provisions the JDK and JAR if missing, sets `JAVA_HOME` and `REA_JADX_MCP_JAR`, then starts `rea-agents@6.5.0 mcp`.
- Remaining prerequisites: Node 22.19+ (REA requires it) and network access on first run. The launcher should fail with a clear message if either is missing.
- Platforms: Linux x64 first. Other platforms need their own JDK URL and checksum.
- Open: where the pinned `jadx-headless-mcp` JAR is published and its license. It is a caller-supplied artifact, so confirm we may download or redistribute it.

## M0 results (2026-10-14)

- REA 6.5.0 needs Node 22.19+, a full JDK and the `jadx-headless-mcp` 0.7.1 JAR. With Temurin 21 and the JAR set, `rea doctor` reports JADX healthy.
- `inspect-android-package` works on both samples: the F-Droid client (12 MB, 11,959 classes, ~14 s) and the MalwareBazaar sample (2.2 MB, ~5 s). The output is JSON of ~40–50 KB, too large to hand to a model whole, so tier 1 should digest it.
- It exposes what tier 1 rules need. The malware sample requests SEND_SMS, RECEIVE_SMS, READ_SMS, READ_CONTACTS, WRITE_CONTACTS, CALL_PHONE, READ_PHONE_NUMBERS and RECEIVE_BOOT_COMPLETED. The F-Droid client requests QUERY_ALL_PACKAGES, REQUEST_INSTALL_PACKAGES and MANAGE_EXTERNAL_STORAGE. The two profiles differ sharply, as a manifest-risk rule needs.
- REA exposes many tools the analyst must not have (adb install/uninstall/push, Frida, gdb, Rizin). The allow-list names read-only Android tools one by one.
- MalwareBazaar's zips are AES-encrypted (password `infected`). The Node core needs a library for this; the machine's tools could not open them.
- MalwareBazaar returned `signature: None` for the newest APK entries, so labels for the benchmark should come from a tag query.
- Verified: `apk-analyst`, run headlessly with the JDK and JAR env set, called `mcp__rea__inspect_android_package` and `mcp__rea__search_android_classes` on the malware sample with no denials. It reported SMS/contacts/boot capabilities and a provisional "likely malicious" verdict, and correctly said it had not decompiled any code. It stopped at manifest and class-name level, so the prompt must push it to read method bodies before confirming a finding. Tool names were `mcp__rea__*` because the user-level REA registration was present.
- Open: with the user-level registration absent, confirm the plugin's own server starts and its tools are named `mcp__rea__*`.


## Deep analysis v2: checklist, planner, investigators (added 2026-10-14)

Why: a single analyst decided for itself when it was done. On `5d84311b…` it stopped after 13 tool calls and listed the manifest, a second dex, a config file and the visible classes as "unknowns" although all were readable.

- **Ledger.** `ledger_init` builds a baseline checklist from the tier 1 report: manifest, entry points, network use, sensitive calls, one item per tier 1 finding, one per distinct native/embedded payload (ABI copies merged), one per small config file, and "read every class" when the dex has 60 classes or fewer. Models can add to it, never remove from it.
- **Planner** (`apk-planner`) takes a quick look and adds 3 to 10 specific questions with `ledger_add`, only before any item is resolved.
- **Investigators** (`apk-investigator`), one per open item, fresh context, up to 4 in parallel, started by the main session (subagents cannot start subagents). An item closes only with `ledger_resolve`: confirmed/rejected with `{where, what}` evidence, or unresolved with a blocker from a fixed list (`packed_native`, `encrypted_payload`, `needs_execution`, `tool_error`, `not_in_sample`). "Not read" is not accepted. New questions come back as leads (rounds 1 to 3, 60 items at most, extras listed as unknowns).
- **Verdict** (`apk-verdict`) sees only the ledger and calls `scan_report`. `scan_report` refuses while any item is open, appends unresolved items to `unknowns`, and lowers the confidence the model asked for when the ledger does not support it (unreadable payload: at most 0.9, or 0.4 for `no_indicators`; any unresolved item with `no_indicators`: 0.5; tool failures: 0.7; a malicious verdict with no confirmed finding: 0.5).
- Open question: parallel investigators each start REA/JADX work on the same APK; check memory use with 4 at once.
