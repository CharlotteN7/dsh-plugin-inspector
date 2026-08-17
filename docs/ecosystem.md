---
title: What it reports on the ecosystem
nav_order: 2
---

# What it reports on the ecosystem

[← dsh-plugin-inspector docs](index.md)


Measured **2026-08-17** against the 40 most-starred GitHub repositories tagged `dsh-plugin` that
publish a resolvable npm package, each pinned to the version it resolved to on 2026-08-16. Re-run
it with `pnpm run sweep`; the corpus is `scripts/ecosystem-corpus.json` and the recorded
measurement is `tests/ecosystem-baseline.json`.

Both columns come from the same corpus and the same pinned versions, so the difference is this
tool's doing and not the ecosystem's. "0.1" is `dsh-plugin-inspector@0.1.0`; "0.2" is this tree,
which reports itself as `0.2.1` because it reads the version out of its own manifest.

| | 0.1 | 0.2 |
|---|---|---|
| Findings | 1,420 | **295** |
| Critical | 252 | **3** |
| Median findings per package | 10.5 | **5.5** |
| Packages with a high or critical | 27 of 40 (68 %) | **21 of 40 (53 %)** |
| Packages failing `--fail-on critical` | 40 of 40 | **1 of 40** |
| Clean packages | 0 of 40 | **0 of 40** |

**The 0.1 README quoted "49 findings, 0 critical" and that number was worthless.** It was measured
on twelve targets — the harness's own bundles and our own sibling plugins — which is a sample
selected for being trusted already. Against published third-party plugins the same build produced
1,420 findings and 252 criticals, and no package came out clean.

Read the 0.2 column honestly:

- **`--fail-on critical` is now a usable gate.** It stops one package in forty. That package,
  `@struktoai/mirage-dsh`, ships a patch layer that switches off `fs-sandbox`, `bash-sandbox` and
  `pwsh-sandbox`, and its three findings lead the report. Under 0.1 the same three sat somewhere in
  a list of 252.
- **The default `--fail-on high` still stops a majority of the ecosystem**, and that is not a
  finished job. The largest remaining driver is `C2` — the analyzer saying it could not read the
  package, on 33 % of the corpus. That is a true statement rather than a false positive, but a gate
  that fires on a third of npm for reasons about the *tool* is not yet a gate.
- **No package is clean, and that is expected rather than alarming.** `C3` alone — "ships built
  output and no source" — fires on 65 % of published packages, because that is what publishing a
  package is. It is `low`, it does not degrade the analysis, and it is not a defect.

A readable report is not yet an installable gate.
