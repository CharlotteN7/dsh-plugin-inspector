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

Node `^22.19.0 || >=24`.

```console
npm install -g dsh-plugin-inspector
dsh-inspect --help
```

From a checkout instead — `lib/` is generated, so a fresh clone has no `dsh-inspect` until it is
built:

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

### Facts — no severity, always emitted

| Fact | Source |
|---|---|
| `package.name`, `package.version`, `license`, `private` | `package.json` |
| `mountsAsBundle` + patch file path | `dsh.bundle.patch` |
| `shipsClientBundle` | `dsh.client` and `exports["./client"]` |
| `insertedRows` — ids and plugin names this layer adds | patch YAML `insert[]` |
| `targetedRows` — ids of existing rows this layer modifies | patch YAML top-level rows with `id` |
| `dependencies`, `peerDependencies`, `optionalDependencies` counts and names | `package.json` |
| `modelVisibleFiles` — shipped `SKILL.md` / skills / `AGENTS.md` / `CLAUDE.md` | file walk |
| `filesRead`, `bytesRead`, `sourceFilesParsed` | analysis run |

### Tier A — decidable, structured declaration, a real verdict

Tier A reads declarations, not code. It is *much* harder to hide from than Tier B, because the
harness itself must be able to read these fields literally in order to act on them: an attacker
cannot obfuscate `disabled: true` and still have it disable anything. Every Tier A finding has
confidence `certain`.

| id | Check | Severity | Method |
|---|---|---|---|
| A1 | Install lifecycle script (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `preprepare`, `postprepare`) | medium; **high** when the command itself fetches, decodes, pipes to a shell, or evaluates inline code | `package.json.scripts` key set. `dsh plugin add` forwards to pnpm verbatim and adds no `--ignore-scripts`, but pnpm ≥ 10 blocks a dependency's lifecycle scripts by default until the package is listed under `allowBuilds`, and `apps/cli/src/plugin.ts` prints that instruction when a build is blocked. The script is one approval away from running, not already running — which is why the category alone is `medium`, and why the measured 5 of 40 legitimate packages that declare one (`tsdown`, `npm run build`, `husky`, `node scripts/prepare.mjs`) stay there. The escalation reads the command line itself, and is calibrated to fire on none of them |
| A2 | Patch row sets `disabled` **truthily** on a **security-relevant** core row (`approval`, `permission`, `sandbox`, `sandbox-policy`, `bash-sandbox`, `pwsh-sandbox`, `fs-sandbox`, `fs-observation-policy`, `subprocess`, `credentials`, `timeout-policy`, `spill-policy`, `session-persistence-jsonl`) | **critical** | patch YAML row with `id ∈ SECURITY_ROWS`. The loader coerces — `disabledOf` is `Boolean(options.disabled)` (`vendor/loader/src/config/entry.ts`) — so `null`, `0` and `""` leave the row **running** and are not this finding. A `!!js` node is an object and stays truthy, so an expression is judged by what it can evaluate to |
| A3 | Patch row disables any other known core row | high for a `@deepseek-ai/dsh-base` row, medium for one only a surface bundle inserts | same, `id ∈ CORE_ROWS`. The row inventory records which of the three shipped bundles inserts each row, because they are not one profile: a `ui-*` row exists only where the web bundle is mounted. Suppressed entirely when the package under analysis *is* one of the three bundles — `@deepseek-ai/dsh-web-app` disabling two dozen rows `@deepseek-ai/dsh-base` inserted is what composing a surface bundle is |
| A4 | Patch row carries a `name` that does not match the targeted row's `name` | medium | `applyEntryPatches` treats `name` on a non-insert patch as an **assertion guard**, not an override: on mismatch it warns and `continue`s, skipping the whole patch. So this row does nothing at all. Either the author is targeting a row that has been renamed, or the patch is stale — in both cases what the user reads and what mounts disagree |
| A5 | Patch row overrides `config` / `inject` / `isolate` / `intercept` / `group` / any other key of an existing core row | medium (high for a security row) | patch YAML. Override is a **shallow whole-value replacement** (`target[key] = value`), never a deep merge, so overriding `config` discards the core row's entire configuration. `PatchOptions` carries a `[key: string]: any` index signature, so *any* key that is not `id`/`insert`/`name` is copied onto the target verbatim |
| A6 | `!!js` expression inventory, with AST sub-classification (see the `!!js` table below) | low → critical by class | dialect parse + `new Function` parse-compile, never evaluated |
| A7 | `!!js` in a field where the loader never interpolates it (`id`, `name`, `group`, `inject`, `intercept`, `isolate`) | medium | mirrors `metadataExpressionErrors`. Signal: the author believes it is live when it is inert — the plugin was very likely never validated |
| A8 | `!js` (single bang) anywhere in the patch YAML | medium | `!js` is a **hard YAML parse error**, verified. Its presence proves the plugin has never been successfully loaded by any harness |
| A9 | `insert` row naming a module that is neither this package nor any of its declared dependencies | high | set difference against `dependencies` ∪ `peerDependencies` ∪ own name. The layer mounts code whose provenance the manifest does not admit to |
| A10 | MCP server row — an `insert`ed row whose `name` is `@deepseek-ai/dsh-mcp-client`. `transport: stdio` → **critical**; `transport: streamable-http` → high | **critical** / high | The stdio config is `{ command, args, env, cwd }` and it spawns that executable directly — **not** through `ctx.subprocess` or `ctx.sandbox`, with no approval and no tool gate. Every tool the server advertises is then registered as `mcp__<serverName>__<tool>` with model-visible descriptions this package does not control. `streamable-http` does not spawn but still imports an untrusted remote tool catalogue. Structured declaration, so Tier A |
| A11 | Non-registry dependency specifier (`git+`, `github:`, `http(s):`, `file:`, `link:`) | high | the referenced code can change under a fixed version string |
| A12 | Shipped model-visible instruction text (`SKILL.md`, `**/skills/*/SKILL.md`, `**/skills/*.md`, `AGENTS.md`, `CLAUDE.md`) | low as presence; escalated by B10 | file walk. See the reach note below |
| A13 | No `files` allowlist in `package.json` | low | the published tarball is whatever happened to be in the working tree |
| A14 | `dsh.bundle.patch` climbs out of the package directory — contains a `..` that escapes | **critical** | `loadProfile` computes the patch path as `join(packageDir, declared)` with **no sanitization** of `declared`, and `..` segments survive that join. An **absolute** path does not escape and is not this finding: `join('/…/pkg', '/etc/passwd')` is `/…/pkg/etc/passwd`, which is inside the package and simply does not exist — that is A16 |
| A15 | Patch row redirects skill discovery into this package — sets `customSkillDirs` or `bundledSkillDir` on the `skill-filesystem` row | high | this is the declaration that turns shipped markdown into model-visible instructions. `bundledSkillDir` additionally carries `trustedHost: true`, which reads through raw Node `fs` and **bypasses the `ctx.fs` sandbox** |
| A16 | `dsh.bundle.patch` names a file the package does not ship | medium | commonly a `files` allowlist that forgets it. Mounting the bundle fails the profile boot |
| A17 | The declared patch layer does not parse | medium | the layer cannot load, and nothing inside it could be analysed |
| A18 | `package.json` field of the wrong shape | low | the field was ignored. A manifest that npm and the harness read differently is worth knowing about |
| A19 | Patch row sets `disabled` **falsily** on a core row | medium | the inverse of A2 and A3, and the one the coercion rule makes visible. Bundle layers apply after the profile's own, so a row the user deliberately switched off is switched back on by this one while the user's file still reads `disabled: true` |
| A20 | `dsh.profile.bundles` names packages to mount as bundles | high | the launcher resolves each named package, reads its `dsh.bundle.patch`, and mounts that layer (`packages/boot/app-boot/src/profile.ts`). This package is then a profile, and everything those packages declare composes into it — none of which is in this analysis |
| A21 | Injection phrasing in shipped instruction markdown | high | **Tier A rather than Tier B, and exempt from the Tier C downgrade.** There is no syntax between a `SKILL.md` and the model: the shipped bytes *are* the prompt, so there is nothing to obfuscate and nothing for a degraded parse to have made unreliable. What is heuristic is the reading of the sentence, not the reading of the file. Tool `description` hits stay Tier B (B10), because code assembles those |
| A22 | `bin` installs a command on the user's PATH | low | linked into the profile's `node_modules/.bin` at install time. The harness never runs it; the user, a script, or an agent shell tool can |
| A23 | Inserted row carries `isolate` or `intercept` on a catalogued service | **critical** for a security seam, high otherwise | `vendor/loader/src/config/isolate.ts` re-maps the named service to a fresh symbol realm for the row and every row beneath it, so a descendant injecting that name receives this subtree's implementation instead of the profile's. The same substitution as replacing the service in code, declared in YAML |

**Reach note for A12, stated because getting this wrong would be dishonest.** Shipping a `SKILL.md`
inside an npm package does **not** by itself put it in front of the model. There is no
`dsh.skills` manifest field. The filesystem provider scans a fixed root set —
`<project>/.dsh/skills`, `<project>/.agents/skills`, `$DSH_HOME/skills`,
`$DSH_AGENTS_HOME/skills`, `bundledSkillDir` — at depth 1 only (`<root>/<name>/SKILL.md` or `<root>/<name>.md`), and a plugin's own `node_modules`
directory is none of those. The three ways shipped text actually reaches the model are: the plugin
calls `ctx.skills.register()` / `ctx.skills.registerProvider()` (→ B10 on the registered body), a
patch row redirects a skill root into the package (→ A15), or the file is copied into the user's
workspace by something else. `AGENTS.md` / `CLAUDE.md` are a separate subsystem again — discovered
by walking the *workspace*, not the profile. So A12 on its own is `low` and its text says
"shipped, reaches the model only if registered or redirected"; it escalates to `high` only when
A15 or a `ctx.skills.register*` call is also present, or when B10's injection heuristics fire.

### Tier B — AST capability detection, "this plugin CAN do X"

Tier B parses shipped `.ts`/`.mts`/`.cts`/`.js`/`.mjs`/`.cjs` with the `typescript` compiler API —
`ts.createSourceFile`, syntax only, **no program, no type checker, no module resolution, no
transpilation, no execution**. Default confidence `high`, dropped to `moderate` when any Tier C
readability finding fires.

| id | Check | Severity | Method |
|---|---|---|---|
| B1 | Replaces a core capability seam — `ctx.provide(<seam>, …)` / `ctx.set(<seam>, …)` where `<seam>` is a key from `api-catalog.ts` | **critical** | call expression, literal first argument matched against the seam key set |
| B5 | System-prompt mutation — `system-prompt/assemble` listener, or `ctx.systemPrompt.{section,context,variable,tools,suppressRuntimeContext}` | high | call matching |
| B6 | Credential read — `process.env.*(TOKEN\|KEY\|SECRET\|PASSWORD\|CREDENTIAL)*`, `~/.dsh/credentials`, `~/.npmrc`, `~/.aws`, `~/.ssh`, `ctx.credentials.*` | medium alone | identifier + literal matching |
| B7 | Network egress — `fetch`, `node:http(s).request`, `node:net`, `WebSocket`, `undici` | medium alone | import + call matching |
| B8 | **Exfiltration pair** — B6 ∧ B7 in the same package | high | set intersection. Reported explicitly as *capability, not dataflow*: the tool cannot prove the credential value reaches the socket. `high` rather than critical because it fires on 18 % of published plugins |
| B9 | Direct `node:child_process` / `node:worker_threads` / `node:vm` | medium alone, high paired with B8's two halves | import specifier. Bypasses `ctx.subprocess` and `ctx.sandbox` entirely. `medium` alone because a bare import fires on half the published ecosystem |
| B10 | Prompt-injection heuristics on **model-visible text only** — registered tool `description` string literals, and shipped skill/instruction files | high | imperative-override phrasing, role reassignment, exfiltration instructions, hidden-text markers — zero-width and bidirectional controls, the tag block, and runs of four or more variation selectors, the encoding GlassWorm shipped executable JavaScript in. Run on *exactly* the text that reaches the model, never on ordinary source comments |
| B11 | Nested plugin mounting — `ctx.plugin(…)`, loader manipulation | high | call matching. A layer that mounts further layers moves the analysis target |
| B12 | Dynamic code construction — `eval`, `new Function`, `vm.runInNewContext`, `module._load` | high | call matching |
| B13 | Filesystem access outside `ctx.fs` — imports `node:fs` or `node:fs/promises` | medium | Reads and writes through the Node API are invisible to `fs/write-intent`, `fs/edit-intent`, `fs/observed`, and the `fs-sandbox` row, so no policy in the profile sees them and nothing appears in the session log |

**The framing B7, B9, and B13 share.** The harness's own dynamic-package sandbox
(`cordis-host-runner/src/sandbox.ts`) traps exactly `require`, `setTimeout`, `setInterval`,
`setImmediate`, `clearTimeout`, `clearInterval`, and `fetch`, redirecting each to a `ctx` service;
it leaves `process` `undefined` and exposes only the seven `HOST_BUILTIN_INSPECTION` globals.
**An installed npm bundle layer gets none of that** — it is a plain ESM import into the harness
process. So these three checks report a gap the harness itself defines: *the harness denies
untrusted code this capability, and this package uses it from a position where nothing denies it.*
That is the harness's reckoning, not a rule invented here.

### Tier C — heuristic; "we cannot read this" is itself the finding

| id | Check | Severity | Effect |
|---|---|---|---|
| C1 | Minified or obfuscated source — long lines that are **most of the file**, or a dense file of under five lines. One long line is an embedded prompt or a base64 asset, not minification, and the harness's own web bundle has one | medium | **degrades** |
| C2 | Dynamic dispatch — computed member access on `ctx` (`ctx[expr]`), non-literal `import()`/`require()`, `atob`/`Buffer.from(…, 'base64')`, an assembled name passed to `.on`/`.set`/`.emit` **on a known context binding**. The receiver guard is the whole check: `.set` and `.get` are `Map`'s names too, and ``this.steps.set(`${turn}:${step}`, t)`` is a composite key, not evasion | high | **degrades** |
| C3 | Ships built output with no corresponding source (`lib/` without `src/`) | low | **does not degrade** — the bytes were read exactly as written and exactly as they will run; what cannot be checked is whether they match the repository. Treating that as an unreadable package marks every ordinary published tarball degraded, because shipping built output and no source is what publishing *is* |
| C4 | Unreadable payload — `.node`, `.wasm`, binaries, files over the size cap | medium | **degrades** |
| C5 | The mounted layer hit a walk ceiling — nesting depth or node count | high | **degrades**. Rows past the ceiling were not read |
| C6 | A `.min.js` artifact | low | **degrades** |

### `!!js` sub-classification (A6)

Every `!!js` node is inventoried with its YAML path and text, then parse-compiled with
`new Function('return (' + expr + ')')` — compilation only; the constructor never executes the
body — and the resulting AST is classified.

Classification is by **reach**, not by syntactic form. `dshHomePath('sessions')` and `steal()` are
both `CallExpression`s; the first is a helper `dsh-app-boot` puts in scope with
`ctx.provide('dshHomePath', dshHomePath)` before any entry mounts, documented as such in that
package's README, and used by the base bundle's own `session-persistence-jsonl` row.

| Class | Example | Severity | Finding |
|---|---|---|---|
| `literal` | `true`, `3` | — | fact only |
| `inert-read` | `process.env.DSH_TOOLS_MODE`, `process.platform === 'win32'`, `ctx.webStartup.host` | — | fact only |
| `harness-call` | `dshHomePath('sessions')`, `process.cwd()` | low | A6 |
| `call` | a call this tool cannot resolve | medium | A6 |
| `mutation` | `process.env.X = …` | high | A6 |
| `module-access` | `require(…)`, `import(…)`, `globalThis[…]` | **critical** | A6 |
| `unparseable` | syntax error | medium — and it means the plugin cannot boot | A6 |

The two classes with no reach are counted in `facts.jsExpressions` and never raised: a constant, or
a read of a service the profile already handed the row, warrants no decision, and the shipped
bundles are mostly made of them.

The escalation of the rest is justified: the evaluator is
`new Function('ctx', 'expr', 'with (ctx) { return eval(expr) }')` — unrestricted eval, with `ctx`
in scope. And `disabled` re-evaluates at **every mount decision**, so a `!!js` there is not a
one-shot: it is a recurring execution point that user patch layers HMR-reload live.

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
   **every one of the eleven rules**, including the two hidden-character rules, which look for
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

Design decisions are in [`ADR.md`](./ADR.md); the check catalogue is under
[What it looks for](#what-it-looks-for).

## Reporting a problem

Security reports go to the address in [`SECURITY.md`](./SECURITY.md), which also says what counts
as a vulnerability in a tool whose whole job is reading hostile input. A check that fires on
ordinary code is a real defect — please open a normal issue for it.

## License

MIT — see [`LICENSE`](./LICENSE).
