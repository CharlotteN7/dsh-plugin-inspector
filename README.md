# dsh-plugin-inspector

**Know what a plugin does before you install it.**

`dsh-inspect` reads a DeepSeek Harness plugin — a directory or an npm tarball — and tells you
what it declares and what its code is capable of. It does not install it, build it, import it,
spawn it, or evaluate any part of it.

```console
$ npm pack some-dsh-plugin@1.4.0 --pack-destination /tmp
$ dsh-inspect /tmp/some-dsh-plugin-1.4.0.tgz
```

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

There are roughly 3,800 repos tagged `dsh-plugin`, and no registry, no review, and no signing
between any of them and your process. This tool exists so that the moment before you install one
is not a blank.

## What you get

The report has two halves, and the first one is the point of the tool.

**Facts** — no severity, always printed. Whether the package mounts as a patch layer and from
which file, whether it ships a browser bundle, which rows it inserts and which existing rows it
modifies, its dependencies, what model-visible text it ships, and how much of it could be read.
A well-behaved plugin has a full facts section and an empty findings section. That is a useful
answer, not an empty one.

**Findings** — ranked, in three tiers:

| Tier | What it reads | What it can say |
|---|---|---|
| **A** | Structured declarations: `package.json` keys, Cordis patch rows, the `!!js` expression inventory | A verdict. Confidence is `certain`, because the harness reads the same bytes the same way |
| **B** | Shipped source, through the TypeScript parser | A capability report: "this plugin **can** do X" |
| **C** | Whether the package could be read at all — minification, computed names, sourceless builds, binaries | That the analysis is degraded, and that no Tier B negative can be trusted |

Every Tier B and Tier C finding carries a `bypass` field naming the one-line evasion for that
specific check. It is inside the finding, not in a footnote, so a report cannot be rendered
without its caveat.

## Usage

```
dsh-inspect <target> [options]

  <target>                A plugin directory, or an npm tarball (.tgz / .tar.gz).

Options
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

Never `pnpm add` a package you have not read. Two safe ways to get the bytes:

```console
# From the registry. `npm pack` on a registry spec downloads and repacks; it does not install
# and does not run the package's scripts.
npm pack <name>@<version> --pack-destination /tmp
dsh-inspect /tmp/<name>-<version>.tgz

# From git. Clone shallow and point the tool at the directory — do NOT use `npm pack` on a git
# spec, which runs the package's `prepare` script.
git clone --depth 1 https://github.com/… /tmp/plugin
dsh-inspect /tmp/plugin
```

A tarball is decoded **entirely in memory**. Nothing is written to disk, which makes tar path
traversal structurally impossible rather than something a filter has to catch.

## What it looks for

Full catalogue with detection methods in [`PLAN.md`](./PLAN.md) §6. The short version:

**Tier A** — install lifecycle scripts; a patch row disabling or rewriting a core row (with
`approval`, `permission`, `sandbox`, `sandbox-policy`, `fs-sandbox`, `fs-observation-policy`,
`subprocess`, `credentials` and friends called out by name); the complete `!!js` inventory,
classified by what each expression reaches; `!!js` in a field the loader never interpolates;
`!js`, which is a hard parse error and proves the layer has never loaded anywhere; inserted rows
naming modules the manifest does not declare; MCP server rows; `dsh.bundle.patch` paths that
escape the package; skill-root redirection; non-registry dependency specifiers.

**Tier B** — capability-seam replacement via `ctx.provide` / `ctx.set`; system-prompt mutation;
credential reads; network egress; the two of those together; `node:child_process`,
`node:worker_threads`, `node:vm`; filesystem access outside `ctx.fs`; runtime code construction;
nested plugin mounting; prompt-injection heuristics run on model-visible text only — shipped
skill markdown and registered tool `description` strings.

**Tier C** — minified source; computed member access, specifiers, and names; build output with
no source; binaries and files over the read caps.

## The ceiling

**This is triage. It is not containment.**

The tool does not run in the harness process, does not gate installation, and cannot stop
anything. It raises the cost of shipping a hostile plugin and gives you something to read where
today you see nothing. That is the whole claim.

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
   authenticated API client trips `B8` legitimately.

### Every Tier B check has a one-line bypass

`ctx['pro' + 'vide']('approval', …)` defeats seam detection. A computed specifier defeats every
import check. A base64 event name defeats every listener check. Splitting a credential read and a
network call across two packages defeats `B8`.

**Tier A is much harder to hide from, because it is structured declaration rather than code.**
The harness must read `disabled: true` literally in order to disable anything, so there is no
obfuscation that leaves it working. That asymmetry is why Tier A issues verdicts and Tier B
issues capability reports.

### And when the tool cannot read the package

If any Tier C check fires, every Tier B confidence drops to `moderate`, `analysis.integrity`
becomes `degraded`, `analysis.negativesReliable` becomes `false`, and the human report is
**forbidden from printing "no findings"**. A clean-looking report on a minified bundle would be
worse than no report, so the tool refuses to produce one.

The honest form of a clean result is: *nothing was found at or above the threshold, in the parts
that could be read.*

## Development

```console
. ../env.sh                 # Node 22.23.2 + pnpm 11.7.0
pnpm install
pnpm run typecheck
pnpm run test               # unit suite, no network, no harness checkout
pnpm run test:coverage
pnpm run test:e2e           # builds, then runs the real binary as a subprocess
pnpm run inspect <target>   # run from source without building
```

Hostile fixtures live in `tests/fixtures/` and are authored here — a plugin that disables the
approval row, one whose `!!js` calls `child_process`, one with a `postinstall`, one pairing a
credential read with `fetch`, one shipping a `SKILL.md` full of injection text, one declaring an
MCP stdio server, a minified one, one using the `!js` tag, one whose bundle patch path escapes the
package, and a benign control that must produce **zero** findings.

`tests/fixtures/execution-canary/` is the proof that nothing runs: its install scripts, its `!!js`
expressions, and its module top level all write a sentinel file, and the test asserts the sentinel
does not exist after a full analysis. `node:child_process` and the write half of `node:fs` are
mocked to throw for the whole suite, so a stray call fails the tests rather than passing quietly.

Design decisions are in [`ADR.md`](./ADR.md); the scope, catalogue, and phasing are in
[`PLAN.md`](./PLAN.md).

## License

MIT
