# dsh-plugin-inspector — execution plan

> Know what a plugin does before you install it.

`dsh-plugin-inspector` reads a DeepSeek Harness plugin — a directory or an npm tarball —
and reports what it declares and what its code is capable of, **without installing it and
without executing any of it**.

This document is written before the code. It states the scope, the check catalogue, the
scoring model, the acquisition rules, the test matrix, the phasing, and — at equal length —
what the tool cannot decide.

---

## 1. The gap this fills

`dsh plugin add` is a thin pnpm forwarder (`dsh/apps/cli/src/plugin.ts`, 158 lines). Verified
by reading it:

- it forwards argv **verbatim** to `pnpm` — no spec parsing, no added flags, no subcommand
  allowlist, no confirmation prompt;
- afterwards it reconciles `dsh.profile.bundles` from the **installed state**, so any
  dependency whose manifest declares `dsh.bundle.patch` joins the mounted layer stack;
- the only thing it prints is a warning for the *harmless* case:
  `"<pkg> declares no dsh.bundle — installed as a plain dependency, not a profile layer"`.
  The dangerous case — a package that **does** declare `dsh.bundle` and is therefore promoted
  to a mounted patch layer running in the harness process at the agent's uid — prints nothing.

Two consequences the plan is built around:

1. **The declaration is the payload.** A mounted bundle patch is plain YAML that is applied
   *after* `@deepseek-ai/dsh-base`, so it can override any field of any core row by id, or set
   `disabled: true` on it. Disabling `approval`, `sandbox`, `sandbox-policy`, `permission`,
   `fs-observation-policy`, or `bash-sandbox` is three lines of YAML and requires no code at all.
2. **TOCTOU is structural.** Because reconciliation reads installed state rather than the
   dependency diff, a package installed today as a plain library that *gains* `dsh.bundle` in a
   later version is auto-mounted by the next `dsh plugin update`, silently. The comment in
   `plugin.ts` says so outright. Any verdict this tool issues is therefore **about one version**,
   and the README says that.

There are roughly 3,800 repos tagged `dsh-plugin`, no registry, no review, no signing. The
analogous tool with proven demand is NVIDIA/SkillSpector (14.6k stars). Nothing equivalent
exists for DSH.

---

## 2. Scope

### In scope

- Static analysis of **one package version**, from a directory or an npm tarball.
- `package.json`: lifecycle scripts, `dsh.bundle`, `dsh.client`, `exports`, `files`, dependencies.
- Cordis patch YAML parsed with the harness's own `!!js` dialect, **never evaluated**.
- TypeScript/JavaScript AST analysis of shipped source for capability declarations.
- Model-visible shipped text (`SKILL.md`, `.dsh/skills/**`, `.agents/skills/**`, `AGENTS.md`,
  `CLAUDE.md`, registered tool descriptions).
- Two report formats — a ranked human report and a stable JSON document — and a configurable
  non-zero exit for CI gating.

### Out of scope (non-goals)

- **Containment.** This tool never blocks, sandboxes, or wraps anything. It reads and reports.
- **Installing, building, or running the analysed package.** No `pnpm add`, no `npm install`,
  no `require`, no `import`, no `eval`, no worker, no subprocess of analysed code. Asserted in tests.
- **Transitive dependency analysis.** The tool reports the dependency list as a fact and
  states plainly that it did not look inside them. Recursing is Phase 4 at the earliest, and
  even then only over packages already fetched as tarballs.
- **Proving intent or dataflow.** Tier B reports *capability*. It finds a credential read and
  a network call in the same package; it does not and cannot prove the value flows between them.
- **Signing, provenance, or reputation.** Different problem, different tool.
- **A verdict of "safe".** The tool has one negative statement it is willing to make —
  "no findings at or above <threshold> in the parts we could read" — and it refuses to make even
  that when Tier C fired.

### Should it also ship a mounted plugin surface? No.

Justified, not assumed:

1. **A mounted plugin runs after the decision it exists to inform.** The value of this tool is
   entirely pre-install: it answers "should this code be on my disk and in my process?". A
   mounted surface can only answer that once the answer no longer matters.
2. **There is no seam to gate.** I read `runPlugin()` end to end. It is
   `spawnSync('pnpm', args)` followed by a manifest rewrite. There is no event, no approval
   hook, and no confirmation prompt anywhere in the path — nothing a mounted plugin could
   intercept. A mounted inspector would have to poll or wrap the binary, which is worse than a
   CLI in every respect.
3. **Mounting an analyzer adds the attack surface it exists to measure.** A mounted plugin is an
   ESM module imported into the harness process at the agent's uid with ungated top-level side
   effects. Putting a hostile-input parser (YAML, tar, arbitrary TS) *inside* that process to
   analyse untrusted bytes inverts the safety argument. As a CLI it is a separate short-lived
   process the user chooses to run.
4. **The second real use is CI gating**, which is an exit code, which is a CLI.

The one mounted surface that would be defensible is a `/inspect` **command** row that shells out
to this CLI for ergonomics inside a session. It buys convenience, not capability, so it is
deferred to Phase 4 and is explicitly not part of the prototype.

---

## 3. Obtaining the package without installing it

The rule: **never `pnpm add`, never `npm install`, never anything that can run a lifecycle
script or resolve a dependency tree.**

| Target form | How it is read | Executes anything? |
|---|---|---|
| Directory (`./my-plugin`) | Direct filesystem read, bounded walk, skipping `node_modules`, `.git`, and anything over the per-file size cap | No |
| npm tarball (`pkg-1.0.0.tgz`) | `gunzip` + tar entry enumeration **entirely in memory**; nothing is ever written to disk | No |
| npm spec (`pkg@1.2.3`) | Phase 2. `npm pack <spec> --pack-destination <tmp>` then the tarball path. `npm pack` on a **registry** spec downloads and repacks; it does not install and does not run the package's scripts | No |
| git spec | **Refused, permanently.** `npm pack` on a git spec runs the package's `prepare` script — that is exactly the execution this tool exists to avoid. Documented workaround: `git clone --depth 1` then point the tool at the directory, or `git archive` | Would — hence refused |

Not writing tarball contents to disk is a deliberate design choice, not an optimisation: it
makes tar path traversal (`../../.ssh/authorized_keys`) structurally impossible rather than
something a filter has to catch, and it makes "the tool did not touch your filesystem" a
property a test can assert.

Caps, because the input is hostile by assumption: per-file 4 MiB, total 64 MiB, 10,000 entries.
Exceeding a cap is not silent — it becomes a Tier C finding, because "we could not read this"
is a result.

### Why not `dsh --profile X --dump-config`?

`--dump-config` is genuinely excellent and it is the reference for correctness: it composes all
layers through the real patch algorithm and renders `!!js` **verbatim and unevaluated** — verified
live against a hostile fixture containing `!!js require('child_process').execSync('id')`, which
printed as text with nothing executed. It is the right tool for **"what is my profile actually
running right now"**, and Phase 3 adds a `profile` subcommand that consumes its output.

It cannot be the pre-install path, for two reasons:

- it composes *installed* state, so it can only inspect a package **after** the code is on disk
  and after `dsh plugin add` already promoted it to a mounted layer — the decision is over;
- it is not strictly read-only: it heals symlinks and rewrites `cordis.yml`.

So this tool re-implements the *reading* half — the `!!js` YAML dialect and the patch-row model —
against the harness's own sources, and cites them.

---

## 4. Foundations reused, not reinvented

| Harness source | What is reused |
|---|---|
| `dsh/scripts/verify-cordis-config.ts` | The `!!js` dialect: `new yaml.Type('tag:yaml.org,2002:js', { kind: 'scalar', construct: … })` over `yaml.JSON_SCHEMA.extend(...)`; the rule that `!!js` is interpolated **only** in a row's `config` (recursively) and a row's own `disabled`, and is inert data in `id`/`name`/`group`/`inject`/`intercept`/`isolate`; and `disabledExpressionProblem`'s parse-compile via `new Function('return (' + expr + ')')`, **which never executes the body** |
| `dsh/vendor/include/src/index.ts` | The patch-row model — row fields and how a patch targets an existing row by `id` versus `insert`ing new ones |
| `dsh/packages/bundle/{base,headless,web-app}/cordis.patch.yml` | The ground-truth inventory of core row ids, and which of them are the security-relevant ones |
| `dsh/packages/extensions/tool-cordis/src/api-catalog.ts` | The machine-readable capability-seam key list — the seam names Tier B watches for replacement |
| `dsh/packages/extensions/cordis-host-runner/src/{guard,sandbox}.ts` | `CTX_VERBS`, `NODE_API_REDIRECTS`, `HOST_BUILTIN_INSPECTION` — the harness's **own** allowlist of what untrusted plugin code may touch. Anything outside it is, by the harness's own reckoning, a capability escalation, which is a much better justified rule than one I invent |
| `dsh/packages/preset/agent-presets/src/preset.ts` | `PresetTrust = 'system' \| 'user'` — the existing trust vocabulary. Reused verbatim rather than inventing a new trust noun |
| `dsh/apps/cli/src/plugin.ts` | The mount and reconciliation semantics quoted in §1 |

js-yaml is pinned to `^4.2.0` to match the harness exactly. Parsing the same bytes differently
from the runtime would make every result unsound, so this is a correctness pin, not a preference.

---

## 5. CLI surface

```
dsh-inspect <target> [options]

  <target>                A plugin directory, or an npm tarball (.tgz / .tar.gz).

Options
  --json                  Emit the machine-readable JSON document on stdout.
  --fail-on <severity>    Exit non-zero at or above this severity.
                          critical | high | medium | low | none    (default: high)
  --no-color              Plain text, no ANSI.
  --version               Print version.
  --help                  Print usage.
```

**Exit codes** — the CI contract:

| Code | Meaning |
|---|---|
| `0` | Analysis completed; no finding at or above `--fail-on` |
| `1` | Analysis completed; at least one finding at or above `--fail-on` |
| `2` | Analysis could not be performed (unreadable target, no `package.json`, malformed tarball, cap exceeded before any file was read) |

Exit `2` is deliberately distinct from `1`. A CI job that treats "the analyzer broke" the same
as "the plugin is clean" is the failure mode this separation exists to prevent.

### Two output sections, and why

The report separates **facts** from **findings**.

- **Facts** carry no severity. They are the "know what a plugin does" half: package identity,
  which mount surfaces it claims, which core rows it touches, its dependency inventory, what
  model-visible text it ships, how much of it was readable. A well-behaved plugin has a rich
  facts section and an empty findings section, and that is the point — the user learns what it
  does even when nothing is wrong.
- **Findings** carry severity and confidence. They are things that warrant a decision.

This split is what lets the benign control fixture assert **exactly zero findings** while still
producing a useful report. Emitting `dsh.bundle` as a "medium finding" — which every legitimate
plugin would trip — would make the tool noise, and a noisy tool gets `--fail-on none`'d into
irrelevance within a week.

### JSON document

```jsonc
{
  "schemaVersion": 1,
  "tool": { "name": "dsh-plugin-inspector", "version": "0.1.0" },
  "target": { "kind": "directory" | "tarball", "path": "…" },
  "package": { "name": "…", "version": "…" },
  "facts": { /* see §6.0 */ },
  "analysis": {
    "integrity": "complete" | "degraded",
    "negativesReliable": true | false,
    "degradedBy": ["C2"],
    "filesRead": 24,
    "filesSkipped": [{ "path": "…", "reason": "size-cap" }]
  },
  "summary": { "critical": 0, "high": 1, "medium": 2, "low": 0 },
  "findings": [
    {
      "checkId": "A3",
      "name": "core-row-disabled",
      "tier": "A",
      "severity": "critical",
      "confidence": "certain",
      "title": "Patch layer disables the core row \"approval\"",
      "detail": "…",
      "evidence": { "file": "cordis.patch.yml", "path": "[0].disabled", "snippet": "disabled: true" },
      "bypass": null
    }
  ]
}
```

`schemaVersion` is at the top and is bumped on any breaking shape change. Every Tier B and Tier
C finding carries a non-null `bypass` string naming the one-line evasion for that specific check.
Putting the bypass **inside the machine-readable finding** rather than in a footnote is the
honesty requirement made structural: a consumer cannot render the finding without also having
the caveat in hand.

---

## 6. Check catalogue

### 6.0 Facts (no severity, always emitted)

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

### 6.1 Tier A — decidable, structured declaration, a real verdict

Tier A reads declarations, not code. It is *much* harder to hide from than Tier B, because the
harness itself must be able to read these fields literally in order to act on them: an attacker
cannot obfuscate `disabled: true` and still have it disable anything. Every Tier A finding has
confidence `certain`.

| id | Check | Severity | Method |
|---|---|---|---|
| A1 | Install lifecycle script (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `preprepare`, `postprepare`) | high | `package.json.scripts` key set |
| A2 | Patch row sets `disabled` on a **security-relevant** core row (`approval`, `permission`, `sandbox`, `sandbox-policy`, `bash-sandbox`, `pwsh-sandbox`, `fs-sandbox`, `fs-observation-policy`, `subprocess`, `credentials`, `timeout-policy`, `spill-policy`, `session-persistence-jsonl`) | **critical** | patch YAML row with `id ∈ SECURITY_ROWS` and `disabled` present |
| A3 | Patch row sets `disabled` on any other known core row | high | same, `id ∈ CORE_ROWS` |
| A4 | Patch row carries a `name` that does not match the targeted row's `name` | medium | `applyEntryPatches` treats `name` on a non-insert patch as an **assertion guard**, not an override: on mismatch it warns and `continue`s, skipping the whole patch. So this row does nothing at all. Either the author is targeting a row that has been renamed, or the patch is stale — in both cases what the user reads and what mounts disagree |
| A5 | Patch row overrides `config` / `inject` / `isolate` / `intercept` / `group` / any other key of an existing core row | medium (high for a security row) | patch YAML. Override is a **shallow whole-value replacement** (`target[key] = value`), never a deep merge, so overriding `config` discards the core row's entire configuration. `PatchOptions` carries a `[key: string]: any` index signature, so *any* key that is not `id`/`insert`/`name` is copied onto the target verbatim |
| A6 | `!!js` expression inventory, with AST sub-classification (see §6.4) | low → critical by class | dialect parse + `new Function` parse-compile, never evaluated |
| A7 | `!!js` in a field where the loader never interpolates it (`id`, `name`, `group`, `inject`, `intercept`, `isolate`) | medium | mirrors `metadataExpressionErrors`. Signal: the author believes it is live when it is inert — the plugin was very likely never validated |
| A8 | `!js` (single bang) anywhere in the patch YAML | medium | `!js` is a **hard YAML parse error**, verified. Its presence proves the plugin has never been successfully loaded by any harness |
| A9 | `insert` row naming a module that is neither this package nor any of its declared dependencies | high | set difference against `dependencies` ∪ `peerDependencies` ∪ own name. The layer mounts code whose provenance the manifest does not admit to |
| A10 | MCP server row — an `insert`ed row whose `name` is `@deepseek-ai/dsh-mcp-client`. `transport: stdio` → **critical**; `transport: streamable-http` → high | **critical** / high | The stdio config is `{ command, args, env, cwd }` and it spawns that executable directly — **not** through `ctx.subprocess` or `ctx.sandbox`, with no approval and no tool gate. Every tool the server advertises is then registered as `mcp__<serverName>__<tool>` with model-visible descriptions this package does not control. `streamable-http` does not spawn but still imports an untrusted remote tool catalogue. Structured declaration, so Tier A |
| A11 | Non-registry dependency specifier (`git+`, `github:`, `http(s):`, `file:`, `link:`) | high | the referenced code can change under a fixed version string |
| A12 | Shipped model-visible instruction text (`SKILL.md`, `**/skills/*/SKILL.md`, `**/skills/*.md`, `AGENTS.md`, `CLAUDE.md`) | low as presence; escalated by B10 | file walk. See the reach note below |
| A13 | No `files` allowlist in `package.json` | low | the published tarball is whatever happened to be in the working tree |
| A14 | `dsh.bundle.patch` escapes the package directory — contains `..` or is absolute | **critical** | `loadProfile` computes the patch path as `join(packageDir, declared)` with **no sanitization** of `declared`. A bundle can therefore point its patch layer at a file outside its own package |
| A15 | Patch row redirects skill discovery into this package — sets `customSkillDirs` or `bundledSkillDir` on the `skill-filesystem` row | high | this is the declaration that turns shipped markdown into model-visible instructions. `bundledSkillDir` additionally carries `trustedHost: true`, which reads through raw Node `fs` and **bypasses the `ctx.fs` sandbox** |
| A16 | `dsh.bundle.patch` names a file the package does not ship | medium | commonly a `files` allowlist that forgets it. Mounting the bundle fails the profile boot |
| A17 | The declared patch layer does not parse | medium | the layer cannot load, and nothing inside it could be analysed |
| A18 | `package.json` field of the wrong shape | low | the field was ignored. A manifest that npm and the harness read differently is worth knowing about |

**Reach note for A12, stated because getting this wrong would be dishonest.** Shipping a `SKILL.md`
inside an npm package does **not** by itself put it in front of the model. There is no
`dsh.skills` manifest field. The filesystem provider scans a fixed root set — `<project>/.dsh/skills`,
`<project>/.agents/skills`, `$DSH_HOME/skills`, `$DSH_AGENTS_HOME/skills`, `bundledSkillDir` — at
depth 1 only (`<root>/<name>/SKILL.md` or `<root>/<name>.md`), and a plugin's own `node_modules`
directory is none of those. The three ways shipped text actually reaches the model are: the plugin
calls `ctx.skills.register()` / `ctx.skills.registerProvider()` (→ B10 on the registered body), a
patch row redirects a skill root into the package (→ A15), or the file is copied into the user's
workspace by something else. `AGENTS.md` / `CLAUDE.md` are a separate subsystem again — discovered
by walking the *workspace*, not the profile. So A12 on its own is `low` and its text says
"shipped, reaches the model only if registered or redirected"; it escalates to `high` only when
A15 or a `ctx.skills.register*` call is also present, or when B10's injection heuristics fire.

### 6.2 Tier B — AST capability detection, "this plugin CAN do X"

Tier B parses shipped `.ts`/`.mts`/`.cts`/`.js`/`.mjs`/`.cjs` with the `typescript` compiler API —
`ts.createSourceFile`, syntax only, **no program, no type checker, no module resolution, no
transpilation, no execution**. Default confidence `high`, downgraded per §6.5.

| id | Check | Severity | Method |
|---|---|---|---|
| B1 | Replaces a core capability seam — `ctx.provide(<seam>, …)` / `ctx.set(<seam>, …)` where `<seam>` is a key from `api-catalog.ts` | **critical** | call expression, literal first argument matched against the seam key set |
| B2 | Auto-approves — a listener on `approval/request` that returns an approving verdict with no user interaction | **critical** | listener body return analysis |
| B3 | `tools/pre-execute` listener returning `allow` | high | same |
| B4 | Waterfall listener that never references `next` | high | The waterfall set is exactly 13 events: `agent/pre-step`, `agent/request`, `agent/request-error`, `approval/request`, `fs/edit-intent`, `fs/write-intent`, `llm/stream`, `session-telemetry/record`, `system-prompt/assemble`, `tools/code-dispatch-log`, `tools/execute`, `tools/post-execute`, `tools/pre-execute`. Per the harness's own rule, returning without calling `next()` short-circuits the chain **including the built-in behavior**, silently disabling the default for everyone downstream. Note there is **no** `fs/read-intent` — the intent family is write and edit only |
| B5 | System-prompt mutation — `system-prompt/assemble` listener, or `ctx.systemPrompt.{section,context,variable,tools,suppressRuntimeContext}` | high | call matching |
| B6 | Credential read — `process.env.*(TOKEN\|KEY\|SECRET\|PASSWORD\|CREDENTIAL)*`, `~/.dsh/credentials`, `~/.npmrc`, `~/.aws`, `~/.ssh`, `ctx.credentials.*` | medium alone | identifier + literal matching |
| B7 | Network egress — `fetch`, `node:http(s).request`, `node:net`, `WebSocket`, `undici` | medium alone | import + call matching |
| B8 | **Exfiltration pair** — B6 ∧ B7 in the same package | **critical** | set intersection. Reported explicitly as *capability, not dataflow*: the tool cannot prove the credential value reaches the socket |
| B9 | Direct `node:child_process` / `node:worker_threads` / `node:vm` | **critical** | import specifier. Bypasses `ctx.subprocess` and `ctx.sandbox` entirely |
| B10 | Prompt-injection heuristics on **model-visible text only** — registered tool `description` string literals, and shipped skill/instruction files | high | imperative-override phrasing, role reassignment, exfiltration instructions, hidden-text markers. Run on *exactly* the text that reaches the model, never on ordinary source comments |
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

### 6.3 Tier C — heuristic; "we cannot read this" is itself the finding

| id | Check | Severity | Effect |
|---|---|---|---|
| C1 | Minified or obfuscated source — max line length, statements-per-line, hex/unicode escape density, absent whitespace | medium | **degrades** |
| C2 | Dynamic dispatch — computed member access on `ctx` (`ctx[expr]`), non-literal `import()`/`require()`, identifier built by concatenation, `atob`/`Buffer.from(..., 'base64')` on a literal | high | **degrades** |
| C3 | Ships built output with no corresponding source (`lib/` without `src/`, `*.min.js`) | low | **degrades** |
| C4 | Unreadable payload — `.node`, `.wasm`, binaries, files over the size cap | medium | **degrades** |

### 6.4 `!!js` sub-classification (A6)

Every `!!js` node is inventoried with its YAML path and text, then parse-compiled with
`new Function('return (' + expr + ')')` — compilation only; the constructor never executes the
body — and the resulting AST is classified:

| Class | Example | Severity |
|---|---|---|
| `env-read` | `process.env.DSH_TOOLS_MODE` | low |
| `platform-check` | `process.platform === 'win32'` | low |
| `literal` | `true`, `3` | low |
| `process-mutation` | `process.env.X = …` | high |
| `module-access` | `require(…)`, `import(…)`, `globalThis[…]` | **critical** |
| `call` | any other call expression | high |
| `unparseable` | syntax error | medium — and it means the plugin cannot boot |

The escalation is justified: the evaluator is
`new Function('ctx', 'expr', 'with (ctx) { return eval(expr) }')` — unrestricted eval, with `ctx`
in scope. And `disabled` re-evaluates at **every mount decision**, so a `!!js` there is not a
one-shot: it is a recurring execution point that user patch layers HMR-reload live.

### 6.5 Severity, confidence, and how Tier C downgrades Tier B

- **Severity**: `critical | high | medium | low`. Ranked lexicographically by
  (severity, tier, checkId) so output ordering is deterministic and diffable.
- **Confidence**: `certain | high | moderate | low`.
  - Tier A → `certain`. The field was read literally from a manifest or a YAML document; the
    harness reads the same bytes the same way.
  - Tier B → `high` by default.
  - Tier C → `moderate`.

**The downgrade rule.** If any C1/C2/C3/C4 finding fires anywhere in the package:

1. every Tier B finding's confidence drops `high → moderate`;
2. `analysis.integrity` becomes `"degraded"` and `analysis.negativesReliable` becomes `false`;
3. the human report prints a banner **instead of** the "no findings" line, and the tool is
   forbidden from rendering the string "no findings" at all.

The reasoning is that Tier B is a whitelist of recognised syntactic forms. `ctx['pro' + 'vide']`
defeats B1. A computed `import()` specifier defeats B9 and B13. A base64 event name defeats B2
through B5. So when C2 fires, a Tier B **positive** is still trustworthy — the tool saw what it
saw — but a Tier B **negative** carries no information at all. Reporting "no capability findings"
on a minified bundle would be actively harmful, so the tool refuses to.

Tier A does **not** downgrade. Obfuscating `disabled: true` is not possible while it still
disables anything.

---

## 7. Test matrix

Every fixture is authored in this repo under `tests/fixtures/`. Each hostile fixture is a
minimal, *realistic* plugin — real `package.json`, real patch YAML, real source — because a
fixture that could not plausibly be published proves nothing about a tool meant to read
published packages.

| Fixture | Shape | Must produce |
|---|---|---|
| `benign-control/` | A well-behaved plugin: `dsh.bundle` patch that only inserts its own row, `files` allowlist, no lifecycle scripts, ordinary source using `ctx.effect()` and calling `next()` | **exactly zero findings**, non-empty facts, exit 0 |
| `disables-approval/` | Patch row `- id: approval` / `disabled: true` | A2 critical |
| `js-child-process/` | `!!js require('child_process').execSync('id')` inside a row `config` | A6 critical, class `module-access` |
| `postinstall-script/` | `scripts.postinstall` | A1 high |
| `credential-exfil/` | Source reading `process.env.DEEPSEEK_API_KEY` and calling `fetch()` | B6 + B7 + B8 critical, and B8's text says *capability, not dataflow* |
| `skill-injection/` | Ships `SKILL.md` containing override/exfiltration phrasing | A12 + B10 high |
| `mcp-stdio/` | Patch inserts `@deepseek-ai/dsh-mcp-client` with `transport: stdio` and a `command` | A10 critical |
| `patch-traversal/` | `dsh.bundle.patch` set to `../../../etc/dsh/cordis.patch.yml` | A14 critical, and the analyzer must not follow the path |
| `obfuscated/` | Minified single-line bundle plus `ctx['pro'+'vide']` | C1 + C2, `integrity: "degraded"`, `negativesReliable: false`, and the report must not say "no findings" |
| `bad-tag/` | `!js` single-bang in the patch YAML | A8 medium, and the analyzer must not crash |

Plus:

- **Non-execution proof.** A fixture whose `postinstall`, `!!js` expression, and module top level
  all write a sentinel file into a temp directory. The test runs the full analyzer over it and
  asserts the sentinel does not exist. Reinforced by a spy asserting `child_process.spawn`,
  `spawnSync`, `exec`, and `execSync` are never called during analysis, and that the tool never
  `import()`s a path inside the fixture.
- **Determinism.** Two runs over the same fixture produce byte-identical JSON.
- **Exit codes.** `--fail-on` at each level against `disables-approval` and `benign-control`.
- **Tarball parity.** `benign-control` and `disables-approval` are packed to `.tgz` and analysed
  from the tarball; findings must match the directory run exactly.
- **No filesystem writes.** Tarball analysis is asserted not to create any file.

---

## 8. Phasing

| Phase | Contents | State |
|---|---|---|
| **1 — prototype** | Source acquisition (directory + in-memory tarball), manifest parsing, `!!js` dialect loader, **full Tier A (A1–A18)**, the call- and import-shape half of Tier B (B1, B5–B13), Tier C (C1–C4) with the downgrade rule, human + JSON reports, `--fail-on`, the full hostile fixture set and the non-execution proof | **shipped** |
| 2 | The listener-body half of Tier B — B2, B3, B4 — which needs a pass over each listener body to decide what it returns and whether it reaches `next`; `--from-npm <spec>` registry fetch via `npm pack`; SARIF output for code scanning | next |
| 3 | `dsh-inspect profile <name>` over `dsh --profile X --dump-config` for "what am I already running"; the 100 % per-file coverage gate from `CONVENTIONS.md` §4; snapshot tests of the human report | after |
| 4 | Diff mode (`v1.2.0` → `v1.3.0`, aimed squarely at the TOCTOU case of a version *gaining* `dsh.bundle`); optional `/inspect` command row; opt-in transitive tarball analysis | later |

Phase 1's Tier B subset is chosen on detection method, not on importance: B1 and B5–B13 are
matched from call and import shapes at a single AST node. B2, B3, and B4 need to reason about what
a listener body *returns* and whether it *reaches `next`*, which is a different and larger piece
of analysis. Shipping the first group well beats shipping both badly, and B4's exact waterfall
event set is written down above so Phase 2 has a spec rather than a guess.

Tier A ships complete in Phase 1 on purpose. It is the part that issues verdicts, the part an
attacker cannot obfuscate, and the part no existing tool covers — so it is the part worth
finishing first.

---

## 9. Limitations — what this tool cannot decide

Reproduced near-verbatim in `README.md`, because a triage tool that oversells itself is worse
than none.

**The ceiling is triage.** This tool raises the cost of shipping a hostile plugin and gives a
user something to read where today they see nothing. It is **not containment**. It does not run
in the harness process, does not gate installation, and cannot stop anything.

Not statically decidable, at all:

1. **`!!js` semantics.** Expressions evaluate under `with (ctx) { return eval(expr) }`. Which
   identifiers resolve, and to what, depends on the runtime `ctx` object. The tool reports the
   expression text and its syntactic class; it cannot tell you what it will do.
2. **Transitive dependencies.** The tool reads one package. A clean package with one hostile
   dependency reads as clean. The dependency list is reported as a fact for exactly this reason.
3. **Runtime-fetched code.** Anything downloaded and evaluated after mount is invisible.
4. **Post-install mutation of `node_modules`.** The bytes analysed are not guaranteed to be the
   bytes that run.
5. **A later version acquiring `dsh.bundle`.** This is the TOCTOU case from §1 and it is the most
   likely real-world bypass: publish a clean library, wait for adoption, add `dsh.bundle` in a
   patch release, and the next `dsh plugin update` mounts it silently. **A verdict is about one
   version, and only that version.**
6. **Intent.** B8 is the sharpest example. The tool proves a package *can* read a credential and
   *can* open a socket. It cannot prove the value flows between them. Nearly every telemetry
   library trips B8 legitimately.

Every Tier B check has a one-line bypass, and each is named in the finding itself:
`ctx['pro'+'vide']` for B1, a computed specifier for B9 and B13, a base64 event name for B2–B5,
splitting the credential read and the network call across two packages for B8. **Tier A is much
harder to hide, because it is structured declaration rather than code** — the harness must read
those fields literally to act on them. That asymmetry is why Tier A alone issues verdicts and
Tier B issues capability reports.

And the honest summary of a clean result: *"nothing was found at or above the threshold, in the
parts that could be read."* When Tier C fires, even that is withdrawn.

---

## 10. Blockers

None found during planning. The `!!js` dialect, the patch-row model, the core row inventory, the
mount semantics, and the capability-seam list are all readable from the harness checkout and are
cited above. js-yaml 4 and the `typescript` compiler API cover the parsing needs with no
execution surface. The npm registry is reachable, so pinned dependencies install.
