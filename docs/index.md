---
title: Why it exists, and what you get
nav_order: 1
---

# Why it exists, and what you get

`dsh plugin add` is a thin pnpm forwarder. It passes your arguments to pnpm verbatim — no spec
parsing, no added flags, no subcommand allowlist, no confirmation prompt — and then reconciles
the profile's layer list from the installed state. Any package whose `package.json` declares
`dsh.bundle.patch` is promoted to a **mounted patch layer**: an ESM module imported into the
harness process at the agent's uid, with ungated top-level side effects, and a YAML layer that
applies *after* `@deepseek-ai/dsh-base` and can therefore override any field of any core row by
id — or set `disabled: true` on it.

The only thing `dsh plugin add` prints is a warning for the harmless case:

```
dsh: warning: <pkg> declares no dsh.bundle — installed as a plain dependency, not a profile layer
```

The dangerous case prints nothing.

There are over 5,000 repos tagged `dsh-plugin` — 5,071 when this was last counted, on 16 August
2026 — and no registry, no review, and no signing between any of them and your process. This tool
exists so that the moment before you install one is not a blank.

## What you get

The report has two halves, and the first one is the point of the tool.

**Facts** — no severity, always printed. Whether the package mounts as a patch layer and from
which file, whether it ships a browser bundle, which rows it inserts and which existing rows it
modifies, the `!!js` inventory of the mounted layer, cordis YAML it ships that nothing mounts,
commands it puts on your PATH, its dependencies, what model-visible text it ships, and how much of
it could be read. A well-behaved plugin has a full facts section and an empty findings section.
That is a useful answer, not an empty one.

**Findings** — ranked, in three tiers:

| Tier | What it reads | What it can say |
|---|---|---|
| **A** | Structured declarations: `package.json` keys, Cordis patch rows, the `!!js` expression inventory | A verdict. Confidence is `certain`, because the harness reads the same bytes the same way |
| **B** | Shipped source, through the TypeScript parser | A capability report: "this plugin **can** do X" |
| **C** | Whether the package could be read at all — minification, names it cannot resolve, a member detached from the receiver Tier B matches it on, sourceless builds, binaries | That the analysis is degraded, and that a Tier B negative about a *name* cannot be trusted. It is not a promise about the heuristics that read content — see [the ceiling](ceiling.md) |

Every Tier B and Tier C finding carries a `bypass` field naming the one-line evasion for that
specific check. It is inside the finding, not in a footnote, so a report cannot be rendered
without its caveat.

A finding is **per package, not per syntax site**. A package importing `node:fs` from eleven files
gets one finding with `occurrences: 11` and three example locations, because the eleventh import
warrants no decision the first did not. Findings are grouped by check and `subject` — the module
specifier, the row id, the seam name, the matched rule — so `node:child_process` and
`node:worker_threads` stay two findings, and a gate can accept `B13`/`node:fs` without accepting
every `B13`.
