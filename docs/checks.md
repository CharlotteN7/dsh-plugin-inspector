---
title: What it looks for
nav_order: 4
---

# What it looks for

[← dsh-plugin-inspector docs](index.md)

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
| A24 | Ships a `binding.gyp` — a native build declaration | medium; **high** when a build step's command line fetches, pipes to a shell, evaluates inline code, or decodes a payload | file presence at the package root, plus a text match for an `actions` / `rules` / `postbuilds` key and the same command signals A1 grades a lifecycle script by. A package that ships this file and declares no `install` or `preinstall` script gets `node-gyp rebuild` as its install command by default, and `node-gyp` evaluates the file to decide what that build does. **The declaration is in none of the entry points a reader checks** — not `main`, not `bin`, not `exports`, not `scripts` — which is the whole reason to read it. It reaches execution through the same `allowBuilds` gate as A1 without needing a key in `package.json` at all. The detail also says when the package ships no C or C++ source, because a gyp with nothing to compile is a build declaration whose only effect is that a build runs. **The file is never parsed and never evaluated** — see the note below |

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

**Why A24 reads `binding.gyp` as text and never parses it.** GYP is Python-ish, not JSON:
single-quoted strings, `#` comments, trailing commas, and `conditions` whose first element is a
Python expression written as a string. `node-gyp` shells out to Python to read it, and there is no
maintained JavaScript parser for the format — so parsing it here would mean hand-rolling one for an
attacker-controlled file, and evaluating a condition is the one thing this tool may never do. It
also would not change the verdict. The decidable half is the whole finding: the file is at the
package root or it is not, and npm's default install command follows from that alone. What
separates a build declaration from a build *step* is an `actions` / `rules` / `postbuilds` key and
the shape of the command under it, and both are literal text either way. So the finding is raised
on presence — which cannot be evaded while the build still happens — and the *grade* reads the
command line, exactly as A1 grades a lifecycle script.

**The base rate this check answers to.** Install-time execution is now off by default: pnpm ≥ 10
and npm ≥ 12 block a dependency's lifecycle scripts until the package is named in `allowBuilds`.
That is why `install-lifecycle-script` is a `medium` category rather than the headline signal, and
it is also why the interesting declarations moved out of `scripts` — to `binding.gyp` and to
editor- and agent-owned files like `.vscode/tasks.json` and `.claude/settings.json`. A24 covers
the first of those. The others are not checked here and this catalogue does not imply they are.

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
| C7 | The mounted layer builds rows out of YAML anchors and aliases. `*a` is not a copy — it hands the loader the same node again, so a row anchored under an inert key can be the row that lands in a live one, and one row in the file can be two in the composed profile. The reader expands every alias to its own node before reading the layer, so the reading matches the loader; the finding stands because the document a person reviews is no longer the document that mounts | medium | **degrades** |
| C8 | An identifier spelled with Unicode escapes — `\u0066etch` for `fetch`, the technique `@kolbo/mcp@1.57.1` (GHSA-pm5r-9rq7-j86p) shipped. One finding per package, naming every distinct name the escapes resolve to | medium | **does not degrade** — see the note below |

**Why C8 does not degrade, and what it is for.** The escape is resolved in the *scanner*, before
any binding, so `\u0066etch` and `fetch` are the same program and no behavior distinguishes them.
That means two different things for the two kinds of reader. A person auditing the file sees
nothing, and so would any check keyed on the spelling of a name — which is what makes this a
technique at all. This tool is not in that group: `ts.createSourceFile` hands back
`node.text === 'fetch'` for the escaped form, so B6, B7, B9 and B12 match escaped spellings exactly
as they match plain ones. That is measured, not assumed —
`tests/fixtures/escaped-identifiers/` ships every name escaped and
`tests/unit/detection.spec.ts` asserts the capability findings that come back. So the escape
defeats the *reading*, not the detection, and treating it as an unreadable package would be false.
It is still worth a finding on its own: nothing writes a name this way by accident, and a published
package has no build reason to.

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
