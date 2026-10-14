---
description: Search the local READroid sample catalog
argument-hint: <package name or sha256 prefix>
allowed-tools: mcp__plugin_readroid_core__catalog_search, mcp__plugin_readroid_core__catalog_sync
---

Search the catalog for: $ARGUMENTS

Call `catalog_search` and list the results (sha256 prefix, package or file name, size, labels). If the catalog is empty, say so and offer to run `catalog_sync` (needs `ABUSECH_API_KEY` in `~/.readroid/.env`).
