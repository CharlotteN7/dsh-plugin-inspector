# dsh-plugin-inspector

**Know what a plugin does before you install it.**

`dsh-inspect` reads a DeepSeek Harness plugin — a directory, an npm tarball, or a published
package fetched by name and checked against the hash the registry published — and tells you what it
declares and what its code is capable of. It does not install it, build it, import it, spawn it, or
evaluate any part of it.

```console
$ dsh-inspect --from-npm some-dsh-plugin@1.4.0
```

## Install

Node `^22.19.0 || >=24`. Once a release is published:

```console
npm install -g dsh-plugin-inspector
dsh-inspect --help
```

Until then the binary comes from a checkout — and `lib/` is generated, so a fresh clone has no
`dsh-inspect` until it is built:

```console
git clone https://github.com/CharlotteN7/dsh-plugin-inspector
cd dsh-plugin-inspector
pnpm install
pnpm run build              # writes lib/, which .gitignore excludes and `files` ships
node lib/cli.js --help      # or `pnpm link --global` for a `dsh-inspect` on PATH
```

To run it from source without building, `pnpm run inspect <target>`.

---

## Why

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
| **C** | Whether the package could be read at all — minification, computed names, sourceless builds, binaries | That the analysis is degraded, and that no Tier B negative can be trusted |

Every Tier B and Tier C finding carries a `bypass` field naming the one-line evasion for that
specific check. It is inside the finding, not in a footnote, so a report cannot be rendered
without its caveat.

A finding is **per package, not per syntax site**. A package importing `node:fs` from eleven files
gets one finding with `occurrences: 11` and three example locations, because the eleventh import
warrants no decision the first did not. Findings are grouped by check and `subject` — the module
specifier, the row id, the seam name, the matched rule — so `node:child_process` and
`node:worker_threads` stay two findings, and a gate can accept `B13`/`node:fs` without accepting
every `B13`.

## What it reports on the real ecosystem

Measured **2026-08-16** against the 40 most-starred GitHub repositories tagged `dsh-plugin` that
publish a resolvable npm package, each pinned to the version current that day. Re-run it with
`pnpm run sweep`; the corpus is `scripts/ecosystem-corpus.json` and the recorded measurement is
`tests/ecosystem-baseline.json`.

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

The gap between "readable report" and "installable gate" is what 0.3 is for.

## Usage

```
dsh-inspect <target> [options]
dsh-inspect --from-npm <name>[@<version>] [options]

  <target>                A plugin directory, or an npm tarball (.tgz / .tar.gz).

Options
  --from-npm <spec>       Fetch a published package from the registry, verify its
                          dist.integrity hash, and analyse it in memory.
  --registry <url>        Registry base URL for --from-npm.
                          (default: https://registry.npmjs.org)
  --json                  Emit the machine-readable JSON document on stdout.
  --fail-on <severity>    Exit 1 at or above this severity.
                          critical | high | medium | low | none    (default: high)
  --no-color              Plain text, no ANSI.
  --version, --help
```

**Exit codes**, which are the CI contract:

| Code | Meaning |
|---|---|
| `0` | Analysis completed; nothing at or above `--fail-on` |
| `1` | Analysis completed; at least one finding at or above `--fail-on` |
| `2` | Analysis could not be performed |

`2` is deliberately distinct from `1`. A job that cannot tell "the analyzer broke" from "the
plugin is clean" is the failure this split exists to prevent.

### Getting a package without installing it

Never `pnpm add` a package you have not read.

```console
# From the registry, in one step. Reads the ~3 KB version document, downloads the tarball into
# memory, verifies dist.integrity BEFORE anything parses it, and analyses it there.
dsh-inspect --from-npm <name>@<version>

# From git. Clone shallow and point the tool at the directory — do NOT use `npm pack` on a git
# spec, which runs the package's `prepare` script.
git clone --depth 1 https://github.com/… /tmp/plugin
dsh-inspect /tmp/plugin
```

`--from-npm` is the only mode that opens a socket, and it is one flag per invocation: it cannot be
combined with a local target, and a directory or tarball scan can never reach it — the fetch lives
in a module the analysis path does not import. **A network fetch is not execution.** No subprocess,
no disk write, no lifecycle script, and no `npm pack`. The report records the tarball URL, the
digest that matched, and the registry's own `hasInstallScript` flag under `target.registry`.

If the hash does not match what the registry published, the tool refuses and parses nothing. If the
package predates `dist.integrity` entirely, the weaker `dist.shasum` is used and the report says
`sha1` rather than claiming more. If neither is published, that is a refusal too.

A tarball is decoded **entirely in memory**, from a file or from a fetch alike. Nothing is written
to disk, which makes tar path traversal structurally impossible rather than something a filter has
to catch. Every read ceiling is applied to the arriving stream rather than to a finished buffer, so
a 28 MB archive holding one 8 GB member is a refusal in under two seconds, not an out-of-memory
kill.

### Directory mode reads the working tree, not "the package"

The two targets are not the same thing and the report says which one you gave it.

A **tarball** is the published package: exactly the bytes a user installs. A **directory** is a
repository checkout, which holds far more — tests, fixtures, CI config, build scratch. None of that
is installed, none of it is mounted, and none of it can act on anybody, so the directory reader is
narrowed to the set `npm pack` would produce: the `files` allowlist when the manifest declares one,
otherwise `.npmignore` or `.gitignore` under npm's defaults. The facts section names which rule it
used and how many working-tree files it skipped.

This matters more than it sounds. Reading a checkout whole means a hostile *test fixture* — a file
that ships nowhere and mounts nothing — is reported at `critical` with `certain` confidence. That
is not a conservative error; it is the tool being confidently wrong about the one tier it treats as
a verdict.

## What it looks for

Full catalogue with detection methods in [`PLAN.md`](./PLAN.md) §6. The short version:

**Tier A** — install lifecycle scripts; a patch row disabling, re-enabling, or rewriting a core row
(with `approval`, `permission`, `sandbox`, `sandbox-policy`, `fs-sandbox`, `fs-observation-policy`,
`subprocess`, `credentials` and friends called out by name); the `!!js` inventory, classified by
what each expression reaches; `!!js` in a field the loader never interpolates; `!js`, which is a
hard parse error and proves the layer has never loaded anywhere; inserted rows naming modules the
manifest does not declare; rows that re-map a service for their subtree with `isolate` or
`intercept`; MCP server rows; `dsh.bundle.patch` paths that climb out of the package;
skill-root redirection; a `dsh.profile.bundles` list, which makes the package a profile that mounts
other packages; commands installed on your PATH; non-registry dependency specifiers; and injection
phrasing in shipped instruction markdown, which is Tier A because the shipped bytes *are* the
prompt.

**Tier B** — capability-seam replacement via `ctx.provide` / `ctx.set`; system-prompt mutation;
credential reads; network egress; the two of those together; `node:child_process`,
`node:worker_threads`, `node:vm`; filesystem access outside `ctx.fs`; code built at runtime **and
called**; nested plugin mounting; injection phrasing in registered tool `description` strings,
which code assembles and which is therefore evadable.

**Tier C** — minified source; computed member access, specifiers, and names; binaries and files
over the read caps; a patch layer whose structure hit a walk ceiling; and build output with no
source beside it, which is the one Tier C finding that does *not* degrade the analysis — the bytes
were read exactly as they will run, and only their provenance is unverifiable.

## The ceiling

**This is triage. It is not containment.**

The tool does not run in the harness process, does not gate installation, and cannot stop
anything. It raises the cost of shipping a hostile plugin and gives you something to read where
today you see nothing. That is the whole claim.

A seam at which an install *could* be stopped does exist — `dsh plugin add` runs pnpm in the
profile directory, pnpm honours a `.pnpmfile.cjs` there, and throwing from its async `readPackage`
hook aborts the install with nothing written to `node_modules`. Nothing in 0.2 uses it.
[`ADR.md`](./ADR.md) §11 records the seam and why shipping a gate on this release's calibration
would have burned the idea.

### What is not statically decidable

1. **`!!js` semantics.** The loader evaluates these with
   `new Function('ctx', 'expr', 'with (ctx) { return eval(expr) }')` — unrestricted eval, under
   `with (ctx)` scoping. Which identifiers resolve, and to what, depends on the runtime context
   object. This tool reports the expression text and its syntactic class. It cannot tell you what
   the expression will do.
2. **Transitive dependencies.** One package is read. A clean package with one hostile dependency
   reads as clean. The dependency list is printed as a fact for exactly this reason.
3. **Runtime-fetched code.** Anything downloaded and evaluated after mount is invisible.
4. **Post-install mutation of `node_modules`.** The bytes analysed are not guaranteed to be the
   bytes that run.
5. **A later version acquiring `dsh.bundle`.** Reconciliation is by *installed state*, not by
   dependency diff. A package installed today as a plain library that gains a `dsh.bundle`
   declaration in a patch release is mounted automatically by the next `dsh plugin update`, with
   no notice. This is the most likely real-world bypass, and it means **a verdict is about one
   version and only that version.**
6. **Intent.** Tier B's `B8` is the sharpest case: the tool proves a package *can* read a
   credential and *can* open a socket. It has not shown that the value flows between them, and it
   cannot — that needs value tracking this tool does not do. Any telemetry library or
   authenticated API client trips `B8` legitimately. It fires on 18 % of published plugins, which
   is why it is `high` and not `critical`.
7. **Injection phrasing that is not spelled in ASCII.** The injection heuristics are Latin-alphabet
   regexes. Substituting Cyrillic homoglyphs — `о` U+043E for `o`, `е` U+0435 for `e` — defeats
   **every one of the ten rules**, including the zero-width-character rule, which looks for
   invisible characters and not for visible ones that are the wrong letter. Verified against the
   rule table, not assumed. Normalisation is not in 0.2; do not read a clean `A21`/`B10` as
   evidence that shipped markdown carries no instructions.

### Every Tier B check has a one-line bypass

`ctx['pro' + 'vide']('approval', …)` defeats seam detection. A computed specifier defeats every
import check. A base64 event name defeats every listener check. Splitting a credential read and a
network call across two packages defeats `B8`. A Cyrillic `о` defeats every injection rule.

**Tier A is much harder to hide from, because it is structured declaration rather than code.**
The harness must read `disabled: true` literally in order to disable anything, so there is no
obfuscation that leaves it working. That asymmetry is why Tier A issues verdicts and Tier B
issues capability reports.

### And when the tool cannot read the package

If any Tier C check that says something could not be *read* fires, every Tier B confidence drops to
`moderate`, `analysis.integrity` becomes `degraded`, `analysis.negativesReliable` becomes `false`,
and the human report is **forbidden from printing "no findings"**. A clean-looking report on a
minified bundle would be worse than no report, so the tool refuses to produce one.

The honest form of a clean result is: *nothing was found at or above the threshold, in the parts
that could be read.*

## Development

Node `^22.19.0 || >=24` and pnpm are the only requirements. No test reaches a network or a harness
checkout: every registry case injects its own `fetch`, and one of them replaces the global with a
throwing stub to prove a directory or tarball scan never calls it.

```console
pnpm install
pnpm run typecheck
pnpm run test               # unit suite
pnpm run test:coverage      # same suite, with the coverage ratchet
pnpm run test:e2e           # builds, then runs the real binary as a subprocess
pnpm run inspect <target>   # run from source without building
pnpm run sweep -- --check   # the one thing here that DOES use a network
```

`pnpm run sweep` is the ecosystem measurement. It fetches the pinned corpus in
`scripts/ecosystem-corpus.json` through the same verified in-memory path as `--from-npm`, prints the
distribution, and with `--check` exits non-zero when a fresh run is worse than
`tests/ecosystem-baseline.json`. `--discover` rebuilds the corpus from the most-starred repositories
carrying the topic; `--pin` moves every entry to the version current now; `--record` rewrites the
baseline. It runs from its own weekly workflow, never from CI — every other workflow here runs
without a network, and a unit suite that cannot reach one is easier to trust.

Hostile fixtures live in `tests/fixtures/` and are authored here — a plugin that disables the
approval row, one whose `!!js` calls `child_process`, one with a `postinstall`, one pairing a
credential read with `fetch`, one shipping a `SKILL.md` full of injection text, one declaring an
MCP stdio server, a minified one, one using the `!js` tag, one whose bundle patch path escapes the
package, and a benign control that must produce **zero** findings. They are deliberately hostile
and structurally inert; [`tests/fixtures/README.md`](./tests/fixtures/README.md) says why, and
which of them is a live prompt-injection payload you should not copy anywhere.

`tests/fixtures/execution-canary/` is the proof that nothing runs: its install scripts, its `!!js`
expressions, and its module top level all write a sentinel file, and the test asserts the sentinel
does not exist after a full analysis. `node:child_process` and the write half of `node:fs` are
mocked to throw for the whole suite, so a stray call fails the tests rather than passing quietly.

Design decisions are in [`ADR.md`](./ADR.md); the scope, catalogue, and phasing are in
[`PLAN.md`](./PLAN.md).

## Reporting a problem

Security reports go to the address in [`SECURITY.md`](./SECURITY.md), which also says what counts
as a vulnerability in a tool whose whole job is reading hostile input. A check that fires on
ordinary code is a real defect — please open a normal issue for it.

## License

MIT — see [`LICENSE`](./LICENSE).
