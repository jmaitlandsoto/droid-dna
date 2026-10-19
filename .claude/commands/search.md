---
description: Search the local droid-dna sample catalog
argument-hint: <package name or sha256 prefix>
allowed-tools: mcp__core__catalog_search, mcp__core__catalog_sync
---

Search the catalog for: $ARGUMENTS

Call `catalog_search` and list the results (sha256 prefix, package or file name, size, labels). If the catalog is empty, say so and offer to run `catalog_sync` (needs `ABUSECH_API_KEY` in `~/.droid-dna/.env`).
