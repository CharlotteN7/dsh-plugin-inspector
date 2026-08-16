# dsh-plugin-inspector 0.2 — "usable as a gate"

Theme: make the tool's verdicts trustworthy on the real ecosystem. Nothing else on the
roadmap matters until this lands, because every downstream feature — the pnpm install gate,
the capability diff, the mounted shim — amplifies whatever calibration ships underneath it.

## The finding that defines this release

The 0.1 README reports "49 findings, 0 critical" across 12 targets. That measurement was
taken on the harness's own bundles and our three sibling plugins — an unrepresentative
sample. Scanned against the **real ecosystem** (40 top-starred npm-published plugins):

| | 0.1 measured on our sample | 0.1 measured on the ecosystem |
|---|---|---|
| Findings | 49 | **1,420** |
| Critical | 0 | **252** |
| Clean packages | 10 of 12 | **0 of 40** |
| With a high or critical | — | **68%** |

The tool cannot be used as a gate today, and the README's number is misleading.

## Bar for every item

Unit tests, plus the CI non-execution canary must still show no sentinel. The
non-execution guarantee, in-memory tar decoding, parse-only `!!js` classification, and the
Tier C downgrade are load-bearing and must not be weakened by any change here.

---

## I1 — Aggregate findings per package, not per syntax site

**Root cause of the volume.** Findings are emitted per syntax site. Three import-shape
checks produce **81%** of all findings, and a package importing `node:fs` in eleven files
produces eleven findings.

**Change.** Collapse to one finding per check per package, carrying an occurrence count and
up to N example sites (suggest 3). Measured effect: **1,420 → 191**, a median of 5 checks
per package, an 87% reduction with no loss of information.

**Test.** A fixture importing the same module from several files yields exactly one finding
with the correct count and example list.

---

## I2 — Recalibrate severity, starting with B9

**Problem.** `B9` (a bare `import 'node:child_process'`) is hardcoded `critical` and fires
on roughly half the ecosystem. A severity that common is not a severity; it is noise wearing
a severity's clothing. Real signal — a package disabling `fs-sandbox`, a `SKILL.md` carrying
a `curl | sh` pipeline — currently arrives 14th on a list of 1,420.

**Change.**

- `B9` becomes `medium` as a bare import. It escalates to `high` only when paired with a
  credential read or an egress call in the same package — the same pairing logic `B8`
  already implements.
- Re-rank so that Tier A structured findings (a patch layer disabling a core row, an MCP
  stdio row, a lifecycle script) sort **above** every Tier B capability finding regardless
  of severity. A verdict outranks a capability report.
- Review every remaining `critical` against the ecosystem corpus. A severity that fires on
  more than a few percent of legitimate packages is miscalibrated by definition.

---

## I3 — Publish an honest ecosystem baseline, and keep it honest

**Change.**

- Add a repeatable sweep script (`scripts/ecosystem-sweep.ts`) that fetches the top N
  npm-published `dsh-plugin` packages and reports the finding distribution.
- Replace the README's "49 findings, 0 critical" with the **ecosystem** number, dated, with
  the sample described. If the post-fix number is still poor, publish it anyway — a tool
  that overstates its own precision is the failure mode this whole release exists to fix.
- Record the baseline as a checked-in fixture so a future change that regresses calibration
  fails CI rather than shipping.

---

## I4 — `--from-npm <name>` by direct registry fetch

**Problem.** Inspecting a published package today means fetching and packing it yourself.

**Change.** Resolve the packument, read `dist.tarball` and `dist.integrity`, fetch the
tarball into memory, **verify the SRI hash before parsing**, and analyse in memory.

This is *safer* than the previously-planned `npm pack` approach: no subprocess, no disk
write, no lifecycle scripts, and the integrity check is a real one. Registry metadata also
carries `hasInstallScript`, the `dsh` key and `scripts` in ~2 KB without the tarball, so a
fast pre-check is available before any download.

**Constraint.** This adds a network call to a tool whose defining promise is that it does
not execute what it analyses. Network fetch is not execution — but it must be explicit,
opt-in per invocation, and never implicit in a directory or tarball scan.

---

## I5 — Correct ADR §1

ADR §1 says there is no seam at which to gate an install. That is now known to be wrong:
`dsh plugin add` runs pnpm in a workspace root, pnpm honours `.pnpmfile.cjs`, and
`readPackage` fires **async**, receives `pkg.dist.tarball`, can `fetch()`, and **throwing
aborts the install with nothing written to `node_modules`**.

Amend the ADR to record the seam and why the gate is nonetheless **not** being shipped in
0.2 — shipping the highest-ceiling feature on today's calibration would burn the idea. The
gate is 0.3 work, after I1–I3 land.

---

## Out of scope, recorded so it is not re-litigated

- **The `.pnpmfile.cjs` install gate** — 0.3, gated on calibration.
- **A mounted shim** for registry listability — 0.3. The inspector declares no `dsh.bundle`
  by design, which makes it ineligible for the ecosystem's only curated feed; the fix is a
  thin shim that shells out via `ctx.subprocess`, keeping the hostile-input parser out of
  the harness process.
- **Capability diff / TOCTOU watch** — 0.3.
- **A public per-plugin leaderboard** — rejected on evidence, not deferred. UMN, curl and
  Hacktoberfest are all backlash cases, and GitHub's anti-spam terms forbid the outreach.
- **A bundled local classifier** — rejected: 738 MB, license-gated alternatives, ~60%
  accuracy on benign trigger-word text.
