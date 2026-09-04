# Architecture decisions

Non-obvious choices and why they went the way they did. New decisions are appended; a superseded
one is marked, not deleted.

---

## 1. A CLI, not a mounted plugin

**Decision.** `dsh-plugin-inspector` ships as a standalone command. It declares no `dsh.bundle`,
mounts nothing, and never runs inside the harness process.

**Why.** Four reasons, in descending weight.

1. A mounted plugin runs *after* the decision this tool exists to inform. The whole value is
   pre-install: "should this code be on my disk and in my process?" A mounted surface can only
   answer that once the answer no longer matters.
2. ~~There is no seam to gate.~~ **Superseded — see §11.** `runPlugin()` in
   `dsh/apps/cli/src/plugin.ts` is `spawnSync('pnpm', args)` followed by a manifest rewrite — 158
   lines, read end to end. There is no event, no approval hook, and no confirmation prompt anywhere
   *in the harness's* path. What that reading missed is that the absence of a harness seam is not
   the absence of a seam: the `spawnSync` runs pnpm with `cwd` set to the profile directory, and
   pnpm has a hook of its own there. The rest of this reason — that a mounted inspector would have
   to poll or wrap the binary — still holds, and the seam that does exist is a pnpm hook rather
   than a mounted layer, so the decision to ship a CLI is unchanged.
3. Mounting an analyzer adds the attack surface it exists to measure. A mounted layer is an ESM
   module imported at the agent's uid with ungated top-level side effects. Putting a hostile-input
   parser — YAML, tar, arbitrary TypeScript — *inside* that process to chew on untrusted bytes
   inverts the safety argument the tool is making.
4. The second real use is CI gating, which is an exit code, which is a CLI.

**Rejected alternative.** A `/inspect` command row that shells out to this binary for ergonomics
inside a session. It buys convenience, not capability, and it can be added later without changing
anything here. Deferred to Phase 4.

---

## 2. `!!js` is parsed and classified, never evaluated

**Decision.** Expression handling has exactly two steps, both parse-only:
`new Function('return (' + expr + ')')` to learn whether it compiles, and a second parse with
`ts.createSourceFile` to classify what it reaches. The constructed function is discarded without
being called.

**Why.** The `new Function` trick is lifted directly from `dsh/scripts/verify-cordis-config.ts`,
which validates `disabled` expressions the same way and says so in a comment: *"Compilation only —
the constructor never executes the body."* Reusing the harness's own technique means the
"does it parse" answer matches what the harness will decide at boot.

Classification is a second parse rather than a regex because the interesting distinction —
`process.platform === 'win32'` versus `require('child_process').execSync('id')` — is structural.
A regex over expression text would be both leakier and harder to justify.

**Consequence worth stating.** `src/checks/tier-b.ts` reports `new Function` in *analysed* code as
a finding (B12) while this tool uses it itself. That is not inconsistent: the finding is about
constructing code and running it, and B12's own text says the construct only matters when the
result is invoked.

---

## 3. Facts are separated from findings

**Decision.** The report has a `facts` object with no severities and a `findings` array with them.
`dsh.bundle` presence, `dsh.client` presence, the inserted row list, and the dependency inventory
are facts.

**Why.** The first draft made `dsh.bundle` a medium finding — it is, after all, the declaration
that gets a package mounted into the harness process. But every legitimate plugin declares it. A
tool that fires on every legitimate plugin gets `--fail-on none`'d within a week, and then it
catches nothing.

The split also makes the false-positive guard expressible: `benign-control` asserts
`findings.length === 0` exactly, with no "except the expected ones" carve-out, while still
producing a report that answers the question in the tool's tagline.

---

## 4. Tarballs are decoded in memory and never extracted

**Decision.** `src/source.ts` reads a `.tgz` with `tar`'s **list** mode, concatenating each
entry's chunks into a buffer. There is no `extract` call anywhere in the module.

**Why.** Not performance. Two safety properties fall out of it for free:

- Tar path traversal (`../../.ssh/authorized_keys`) becomes structurally impossible rather than
  something a filter has to get right against an adversary.
- "Analysing a package touches no file" becomes a property a test can assert, which
  `tests/unit/source.spec.ts` does by listing the containing directory before and after.

Symbolic links in a directory target are recorded and never followed, for the same reason: a link
pointing outside the package is not part of the package.

**Rejected alternative.** Hand-rolling a tar reader to avoid the dependency. A maintained
dependency is worth taking where it genuinely deletes owned code and owned tests, and hostile-input
parsing — PAX headers, long names, sparse entries — is precisely where a hand-rolled parser goes
wrong.

The pipeline is nonetheless assembled by hand rather than through `tar.list({ file })`. That
convenience path applies no backpressure between the inflater and the parser: the inflater runs
ahead of the entry consumer, and one very large member materialises gigabytes of itself whatever
the consumer does with it. A `stream.pipeline` of Node streams paces the two against each other.
Measured on a 28 MB probe holding one 8 GB member, that is 96 MB of resident memory instead of
4 GB. A counting stage between them fails the read outright past 512 MB of decompressed tar,
because producing eight gigabytes still costs the time to inflate them and a CI job that hangs on
a hostile input is a denial of service with extra steps.

---

## 5. js-yaml is pinned to the harness's `^4.2.0`

**Decision.** Not `^5`, which is current.

**Why.** This is a correctness pin, not a preference. The tool's claims are about what *the
harness* will do with a file. Parsing the same bytes differently from the runtime would make every
downstream result unsound, including the negative ones. The dialect is also constructed the same
way the harness constructs it — `yaml.JSON_SCHEMA.extend(jsExprType)`, deliberately not
`DEFAULT_SCHEMA` — so a tag the harness rejects (`!!binary`, `!!python`) is rejected here too and
surfaces as a finding rather than as quietly parsed data.

---

## 6. Harness ground truth lives in one module

**Decision.** `src/knowledge.ts` holds the core row inventory, the security-relevant row subset,
the capability seam keys, the waterfall event set, and the module tables — each citing the harness
file it was transcribed from.

**Why.** These are facts about one harness version, not opinions, and they will go stale.
Keeping them in one module makes re-syncing against a new harness a single reviewable diff rather
than an archaeology exercise across a dozen check functions. `HARNESS_REFERENCE` records which
version they came from.

The row id → module name map is transcribed from the three shipped bundle patches rather than
hand-typed, because the `name` half is load-bearing: `applyEntryPatches` treats `name` on a
non-insert patch as an assertion guard, so a patch naming the wrong module is silently skipped
in full. Check A4 exists only because that map does.

The two tables the tiers lean on hardest are **exact** against the harness at `HARNESS_REFERENCE`,
not approximations of it: `SEAM_KEYS` holds all 68 `SERVICE_API[].key` values from the tool-cordis
api-catalog, and `CORE_ROWS` holds all 147 row ids the three shipped bundle patches declare —
68 = 68 and 147 = 147, with no id in either direction that the other side does not have. What goes
stale is the harness version they describe, not the completeness of the transcription.

Re-syncing is a diff, not a rewrite, and `0.1.0-rc.5` → `0.1.1-rc.2` is the evidence: five releases
added six rows (all inserted by the web bundle) and three seam keys, renamed nothing, removed
nothing, and left the waterfall event set alone. The one correction that was not drift is
`SANDBOX_DENIED_GLOBALS`, which had listed five traps since 0.1 while the sandbox has always had
seven — `clearTimeout` and `clearInterval` were missed in the original transcription, and
`docs/checks.md` had been naming all seven the whole time.

`0.1.1-rc.2` → `0.1.2-rc.1` is the first sync that subtracts. Thirteen row ids arrived and three
left (`api-gateway`, `client-runtime`, `tool-subagent-report`, whose packages are not published at
this release); four rows moved from the web bundle into the base layer; eleven seam keys arrived
and `apiProxy` left; `tools/code-dispatch-log` is now `tools/ptc-dispatch-log`, and
`user-questions/request` is a new decision waterfall. Subtraction is the half that changes
verdicts rather than adding them: a row id that leaves `CORE_ROWS` stops matching A3 and A5 and
starts matching A26, so the same patch line is graded as reaching another package's row instead of
a shipped one. That is the intended reading at this release, and `tests/unit/checks.spec.ts` pins
all three directions — a dropped id, an added id, and a row whose bundle membership moved.

`scripts/harness-sync.ts` is what makes `HARNESS_REFERENCE` a checkable claim rather than a
remembered one. It reads the three bundle patches and the api-catalog out of the published
tarballs over the same integrity-verified path `--from-npm` uses, parses the catalogue with
`ts.createSourceFile`, and diffs each table in both directions; a scheduled workflow runs it
weekly. It resolves **one** version — the CLI's, because the bundle packages carry dist-tags of
their own and `@deepseek-ai/dsh-base@latest` currently points at `0.0.1-rc.1`, a different row
inventory nobody has installed. Reading each package at its own `latest` would diff the tables
against a harness that does not exist.

The tables have no counterpart in the unit suite beyond `tests/unit/knowledge.spec.ts`, which pins
the sizes and the subset invariants. That file cannot tell whether the tables are *right* — only
the sync script can, and only with a network. What it catches is the edit that drops a row by
accident, and the security subset entry that is not in its parent set and therefore never fires.

---

## 7. Tier C degrades Tier B, and Tier A is exempt

**Decision.** If any Tier C check fires: every Tier B confidence drops `high → moderate`,
`analysis.negativesReliable` becomes `false`, and the human renderer is forbidden from printing
"no findings". Tier A is untouched.

**Why.** Tier B is a whitelist of recognised syntactic shapes. `ctx['pro'+'vide']` defeats B1; a
computed specifier defeats B9 and B13; a base64 event name defeats the listener checks. So under
obfuscation a Tier B **positive** is still trustworthy — the tool saw what it saw — but a Tier B
**negative** carries no information whatsoever. Printing a clean bill on a minified bundle would be
actively harmful, so the renderer refuses.

Tier A does not degrade because obfuscating `disabled: true` is not possible while it still
disables anything. The harness must read that field literally to act on it.

`tests/fixtures/obfuscated/` exists to prove both halves: it hides a `ctx['pro'+'vide']('approval')`
that Tier B genuinely fails to catch, and the test asserts that failure rather than papering over
it.

---

## 8. Prompt-injection heuristics run only on model-visible text

**Decision.** `scanInjection` is applied to shipped skill and instruction markdown and to
registered tool `description` string literals. Not to source comments, not to README files, not to
arbitrary strings.

**Why.** Those two surfaces reach the model verbatim, unescaped and uncapped. Everything else does
not, and scanning it would produce a stream of false positives from documentation that happens to
quote an attack — including, immediately, this repository's own `README.md`.

**"Registered" is a receiver guard, and it is the whole of B10.** A `description` property is only
scanned when the object literal holding it reaches `<ctx>.tools.register(…)` or `defineTool(…)` —
directly, or through a name a later line in the same file registers. `description` is one of the
commonest property names in JavaScript: a JSON schema, an OpenAPI document, a changelog entry and a
CLI option table all carry one, and none of that text goes anywhere near a model. Without the guard
the heuristics run on all of them, and a package's release notes produce a `high` finding titled
"Tool description …" about a tool the package does not have — a confident claim about a surface the
check has not established exists. This is the same guard C2 carries for `.set`/`.get`/`.on`, for
the same reason. Nested properties inside a registered definition do count: a parameter's
`description` is rendered into the schema the model receives alongside the tool's own.

**Honesty note carried in the findings.** These are heuristics over natural language. They will
miss a rephrasing and they can fire on a document that legitimately discusses the subject. Every
B10 finding names which rule matched so the reader can judge it.

**Hidden characters are matched by run length, not by presence.** The rule table carries two
invisible-character rules and they are keyed differently on purpose. Zero-width and bidirectional
controls and the U+E0000 tag block fire on a single occurrence: none of them has a use in a skill
file. Variation selectors do — U+FE0F and U+FE0E select the emoji or text presentation of the
character before them, and the U+E0100 plane carries the Ideographic Variation Sequences CJK text
uses — so firing on one selector would fire on every document with an emoji in it. The rule
therefore keys on a run of four or more. Nothing standardised puts four in a row: a variation
selector modifies the single character it follows, so the second has nothing to modify. GlassWorm
encoded executable JavaScript one byte per selector across five waves, 35,800 installs and 300+
repositories, which makes a real payload an unbroken run of tens to thousands — four is far below
that and above the doubled selectors an editor round-trip produces. Measured cost on the pinned
corpus: zero additional findings across 40 published packages.

---

## 9. `dsh --dump-config` is the reference, not the mechanism

**Decision.** The tool re-implements the reading half of the patch model rather than shelling out
to `dsh --profile X --dump-config`.

**Why.** `--dump-config` is excellent and is the correctness reference: it composes every layer
through the real patch algorithm and renders `!!js` verbatim and unevaluated. But it composes
*installed* state, so it can only inspect a package after the code is already on disk and after
`dsh plugin add` has already promoted it to a mounted layer — the decision is over. It is also not
strictly read-only: it heals symlinks and rewrites `cordis.yml`.

A `dsh-inspect profile <name>` subcommand consuming its output answers a different and also
worthwhile question — "what am I already running" — and is Phase 3.

---

## 10. The coverage gate is a ratchet, not the target

**Superseded — see §20.** The numbers below were aggregate, and an aggregate gate hides the file
that needs the bar most.

**Decision.** `vitest.config.ts` carries the measured numbers, floored to whole percent
(93 % statements, 96 % lines, 97 % functions, 84 % branches), rather than the 100 % per-file bar
this workspace adopts for security code.

**Why.** A gate that fails on every run is not a gate; it is noise that gets removed. Holding the
measured numbers means a regression fails CI today, and the ratchet moves up as the remaining
branches get tests of their own. What matters more than the number is *which* lines are covered:
the resource ceilings, the symlink and escaping-entry refusals, and every check in the catalogue
now have a case, because those are the lines that carry the safety claims. The comment in the
config says exactly this so the number is not mistaken for the target.

---

## 11. There is a seam to gate an install, and this tool deliberately does not use it

**Correction to §1.** §1 reason 2 said there is no seam at which to gate an install. That is
wrong, and it was wrong when it was written. The chain:

- `runPlugin()` calls `spawnSync('pnpm', args, { cwd: profileDir })`
  (`dsh/apps/cli/src/plugin.ts`). Every `dsh plugin add` is a pnpm run whose working directory is
  the profile, which is a pnpm workspace root — the same directory whose `pnpm-workspace.yaml` the
  harness tells the user to edit when a build is blocked.
- pnpm 11.7.0 honours a `.pnpmfile.cjs` in that directory.
- Its `readPackage` hook fires **async**, so a hook may await. It receives the resolved manifest,
  including `pkg.dist.tarball`, and may therefore `fetch()` the very bytes this tool analyses.
- **Throwing from the hook aborts the install with nothing written to `node_modules`.** Not a
  warning after the fact — the package never lands.

That is a real pre-install gate: the decision point this tool exists to inform, at the moment it
still matters, with a refusal that actually refuses.

**Decision.** The seam is recorded and nothing is shipped into it. That still holds at 0.5.

**Why not now.** The gate is the highest-ceiling feature on the roadmap and it inherits whatever
calibration sits underneath it. Measured on 40 published plugins, 0.1 produced 1,420 findings and
252 criticals with no clean package; a `.pnpmfile.cjs` built on that would have refused most of the
ecosystem on its first run. What happens next is not that users tune it — it is that they delete
the file and never try the idea again. An install gate gets one chance to be right, because the
failure mode of a wrong one is not a false positive, it is a broken install of a package the user
wanted.

So calibration lands first. 0.2 takes findings from 1,420 to 295 and criticals from 252 to 3, and
`--fail-on critical` now stops 1 package in 40 rather than 22 in 40. That is the number a gate has
to be built on, and it is the number that says whether the gate is worth building.

**What the gate will have to answer, recorded now so 0.3 does not rediscover it.**

- A hook that fetches every tarball adds a download to every install of every dependency, not just
  the plugin the user named. The registry metadata is ~3 KB and already carries `hasInstallScript`,
  `scripts` and the `dsh` key, so the cheap pre-check runs first and the tarball is fetched only for
  packages that declare `dsh.bundle` (which is what makes a package a mounted layer at all).
- The hook runs *before* the user has seen anything, so its refusal message is the whole user
  interface. It has to name the finding, the file, and how to proceed anyway.
- `.pnpmfile.cjs` is code pnpm runs in its own process. Putting this tool's hostile-input parser
  there re-opens exactly the objection §1 reason 3 raises against mounting. The hook has to shell
  out to the binary, not import the library.
- A hook is repo-local configuration and therefore attacker-controlled under the workspace's own
  trust ranking. A plugin that installs a `.pnpmfile.cjs` weakening the gate is a case the design
  has to answer before the gate ships.

---

## 12. A finding is per package and carries a subject

**Decision.** Checks still match one syntax site at a time, but findings sharing a `checkId` and a
`subject` collapse into one carrying `occurrences` and up to three example sites. The subject is
the module specifier, the row id, the seam name, or the matched rule — what the finding is *about*,
independent of where it was seen.

**Why a subject rather than the title.** Grouping by title would work by accident and break by
accident: Tier C titles named the file they came from, so `C1` would never collapse, while any two
checks that happened to render the same sentence would merge. Grouping by check id alone loses more
than it saves — `node:child_process` and `node:worker_threads` are both `B9`, and no single title is
true of both. The subject is the one field that says what the finding is about with nothing about
where, which is exactly the grouping key. It is emitted in the JSON for the same reason: a gate that
wants to accept `B13`/`node:fs` without accepting every `B13` needs a stable name for it.

**Why not just cap the list at render time.** Because the count is information. "Imports `node:fs`
from one file" and "from ninety files" are different facts about a package, and a renderer that
truncates throws the second one away. The count and the examples live in the finding, so a JSON
consumer sees them too.

**Consequence.** `schemaVersion` is 2. Findings gained `subject`, `examples` and `occurrences`, and
`target.kind` gained `registry`.

---

## 13. Fetching from a registry is a mode, never a fallback

**Decision.** `--from-npm` fetches a packument, downloads the tarball into memory, verifies
`dist.integrity` **before** anything parses a byte, and analyses it. It lives in `src/npm.ts` and
`src/registry.ts`, which `src/inspect.ts` does not import.

**Why the module split matters more than it looks.** "This tool does not run what it analyses" is
the whole claim, and "it does not go to the network unless you asked it to" is now part of keeping
that claim legible. Making the local path *unable* to reach the fetch code — rather than merely not
calling it — turns that into something a reader can check by looking at the imports, and something
a test can hold: the suite replaces the global `fetch` with a throwing stub and inspects a directory
and a tarball through it.

A network fetch is not execution. It writes no file, spawns nothing, and runs no lifecycle script,
which is more than can be said for `npm pack` on a git spec. But it is a side effect the other two
modes do not have, so it is one explicit flag per invocation, and a report records the fetch in
`target.registry` — including the digest that matched.

**Verify before parse, not after.** The order is the point. Hashing after the parser has already
seen the bytes would prove something true about bytes that had already been acted on. `dist.shasum`
is accepted only when a package predates `dist.integrity` entirely, and the report names `sha1` when
that happens rather than saying "verified" and leaving it there. No digest at all is a refusal:
"verified" would be a claim the tool cannot make.

**Origin pinning.** The tarball URL must sit on the registry's own origin. This does not defend
against a hostile registry — it publishes both the URL and the hash — but it stops one doctored
packument on an honest registry from making the tool fetch an arbitrary URL on the user's behalf.

---

## 14. The version in a report is read, not written down

**Decision.** `TOOL_VERSION` is `package.json`'s `version`, read from the manifest one directory
above the module at import time. There is no second copy.

**Why.** The second copy went stale and stayed stale through two releases: every `--json` report,
every `--version`, and the recorded ecosystem baseline said `0.1.0` while the published package was
`0.2.1`. A report that names the wrong build is worse than one that names none — 0.1 and 0.2 are
different check sets and different severities, so a stored report could not be matched to the tool
that produced it. Nothing gated the constant; `publish.yml` compares the git tag against
`package.json` and never looked at `src/`.

Deriving rather than gating, because a gate is another thing to remember and it only fails after
the mistake exists. The manifest resolves at `../package.json` from `src/`, from `lib/` after a
build, and from `package/lib/` inside the published tarball, so one relative path covers every way
the module is loaded. npm always ships `package.json`, so the read cannot miss.

---

## 15. B2, B3 and B4 are out of the catalogue until they are implemented

**Decision.** The README's Tier B table no longer lists B2 (auto-approving `approval/request`
listener), B3 (`tools/pre-execute` returning `allow`), or B4 (waterfall listener that never
references `next`). No id is reused.

**Why.** They were documented with severities and a stated method — "listener body return
analysis" — and never implemented. For a tool whose product is knowing what a plugin does before
you install it, a catalogue entry is a claim: a reader who saw B2 at `critical` had reason to
believe auto-approval detection was covered, and a clean report meant it had been looked for. It
had not. Removing the rows costs the reader nothing they actually had; leaving them cost trust in
every other row.

They are worth building. B4 in particular detects the footgun the workspace conventions name as
the top waterfall hazard — a listener that returns without calling `next()` short-circuits the
chain including the built-in behavior — and doing it properly needs return-path analysis over
listener bodies, which is a different piece of work from matching a call expression.

**The ground truth stays.** `WATERFALL_EVENTS`, `DECISION_EVENTS` and `SANDBOX_DENIED_GLOBALS` in
`src/knowledge.ts` are transcriptions of the harness's `EVENT_API` and `cordis-host-runner`
sandbox, of the same kind as every other table in that module, and they are what B2/B3/B4 will be
built against. `WATERFALL_EVENTS` is already part of the published API surface. Re-deriving them
later from a newer harness would silently change what the checks mean; keeping them dated against
`HARNESS_REFERENCE` is what §6 is for.

---

## 16. A1 is a category at `medium` and a command line at `high`

**Decision.** An install lifecycle script stays `medium`. It becomes `high` when the command
itself fetches a remote resource, pipes into a shell, evaluates inline code, or decodes a payload.

**Why not raise the category.** A lifecycle hook is common in malicious packages, which is an
argument for `high` until the other side is measured. On the pinned corpus, 5 of 40 legitimate
published plugins declare one — `tsdown`, `npm run build`, `husky`, `node scripts/prepare.mjs` —
and two of those five carry no other high or critical finding, so raising the category would move
the default `--fail-on high` gate from 21 packages to 23 for no new information. That is the
mistake 0.2 exists to correct, restated. pnpm ≥ 10 also blocks a dependency's lifecycle scripts
until the package is named in `allowBuilds`, so the category describes something one approval away
from running.

**Why escalate on the command.** A hook whose command line fetches, decodes, or evaluates carries
the whole attack inside `package.json`, with no shipped module at all. That case is decidable
from the manifest, which is Tier A's own standard: the string is the thing that runs. The signal
table is calibrated against the false-positive side rather than against the idea of a build hook —
running a file the package shipped is what a build hook is and is deliberately not a signal, which
is why `node scripts/prepare.mjs` stays `medium`. Measured cost on the pinned corpus: all five A1
findings stay `medium`, and the distribution is unchanged.

---

## 17. The calibration bar moves in one direction

**Decision.** `tests/unit/calibration.spec.ts` asserts only ceilings on the recorded measurement,
and pins the published `critical` share bar to the literal `0.1`.

**Why.** The case that recorded how many packages a default gate stops carried both
`withHighOrCritical <= 21` and `withHighOrCritical / scanned > 0.5`. The second is the first
inverted. At 21 of 40 the margin was one package: calibrating one more package out of the gate
makes the share exactly 0.50, which is not greater than 0.5, so CI would have failed on precisely
the improvement this package exists to produce. A ratchet that punishes progress gets deleted in a
hurry by whoever hits it, and it takes the real half with it.

The bar assertion had the opposite problem. `bar.maxCriticalShareOfCorpus <= 0.1` compares the
baseline against the constant that wrote it — `MAX_CRITICAL_SHARE` in `scripts/ecosystem-sweep.ts`
— so it read `0.1 <= 0.1` and could not fail while the constant was the source of both sides.
Pinning the literal makes moving the published bar in either direction a change a reviewer sees.

---

## 18. A YAML alias is expanded before the layer is read

**Decision.** `parsePatchDocument` expands the loaded document into a tree before the walk: every
occurrence of an anchored node becomes its own node at its own path, bounded by the same node and
nesting ceilings the walk uses. Any layer that used an anchor also raises `C7`, which degrades the
analysis and makes `negativesReliable` false.

**Why.** js-yaml resolves `*a` to the *same JavaScript object* as `&a`. The walk deduplicated by
object identity — a `WeakSet` charged in `admit` — so a node reached twice was analysed once, at
whichever position reached it first. A row anchored in the inert `inject:` slot and aliased into
the patch list was therefore attributed to the inert slot and dropped from the patch list: the
layer disabled the core `approval` row, and the tool printed `rows modified: theme-row`, no
findings above `low`, exit 0, and `integrity: complete` / `negativesReliable: true`. A missed
finding is bad; a missed finding underneath a certificate that the negatives are meaningful is
what makes the tool worse than not running it.

Identity deduplication was never the right rule, because the loader has no such notion.
`interpolate` (`vendor/loader/src/config/utils.ts`) maps over arrays and objects as a tree and
evaluates each `!!js` node it reaches, once per path, and `applyEntryPatches` reads each element of
the patch list on its own. Expanding first makes this module agree with both, and it is why an
anchored expression reached from four paths is now four expression sites rather than one.

The alias bomb that motivated the identity set is still bounded, by the ceilings rather than by
deduplication: the expansion charges every materialised node against `MAX_WALK_NODES` and every
level against `MAX_WALK_DEPTH`, and past either one the subtree becomes `null` and `C5` reports
that the layer was read in part. A 475-byte file describing 31 billion paths through 100 nodes
stops at 200,000 nodes in milliseconds.

`C7` fires even though the expansion is what makes the reading correct. Two reasons. The expansion
is bounded, so an aliased layer is exactly the layer whose reading can be silently truncated. And
an alias means the reviewer and the loader are not looking at the same document — the row a person
sees under `inject:` is the row that mounts — which is a fact about how much a reading of the file
is worth, and that is what Tier C is for.

---

## 19. An unsourced number is removed rather than rounded

**Decision.** The two percentages attributed to "ASE 2026" are gone from `knowledge.ts`, from
`ADR.md` §16, and from the A1 finding text users read. The qualitative claim stays.

**Why.** The attribution carried no title, authors, venue detail, or DOI, and the figures could not
be substantiated. One of them was printed to users inside a finding — *"which is the shape 21.2 %
of malicious npm packages take"* — where a reader has no way to check it and every reason to treat
it as measured. The distinction the sentence exists to draw survives without it: a build hook runs
something the package shipped, and a command line that fetches, decodes, or evaluates does not need
a shipped module at all. That is decidable from the manifest, which is the only claim A1 makes.

Approximating the citation, or keeping the numbers with a softer hedge, would have been worse than
either removing them or finding the source. A security tool's own text is held to the standard it
holds packages to.

---

## 20. The coverage gate is per file, at 100 %

**Supersedes §10.** The thresholds are `perFile: true` at 100 % on lines, statements, functions
and branches. A line that genuinely cannot run carries a `v8 ignore` naming why.

**Why.** §10 was right that a gate failing on every run gets deleted, and the ratchet did move
monotonically upward — branches went 69 → 84 across releases, every commit message saying "raise
the ratchet". What it got wrong is *what* was being ratcheted. The numbers were project-wide, so a
file could sit far below them and pass on the strength of the files above it. `cordis-yaml.ts` was
at 79.69 % branch coverage under an 84 % gate, and the alias-attribution defect that erased a
tier-A critical finding (§18) lived in exactly the branches nothing reached.

Per file, that is not expressible: the gate fails on the file, named, with its own number. The
demonstration is one line — an unreachable branch added to `cordis-yaml.ts` fails the per-file gate
with `Coverage for branches (99.2%) does not meet global threshold (100%) for src/cordis-yaml.ts`
and passes the aggregate gate at 99.89 % without a word.

100 % rather than each file's measured floor, because a per-file gate set to the weakest file is
the aggregate problem again in another shape: it licenses every other file down to that number.
`dsh-dlp` and `dsh-netguard` hold the same bar, and the workspace conventions adopt it for security
code. Reaching it took cases for the paths that carry the safety claims — the tar stream ceilings,
the directory reader's refusals, the publish-set globs, every check in the catalogue and every
severity arm in it — and about two dozen `v8 ignore` comments on defensive guards that are
unreachable because their callers already checked, each stating which caller.

---

## 21. `binding.gyp` is read as text, and the finding is Tier A

**Decision.** A24 fires on the presence of `binding.gyp` at the package root. The file is matched
as text — never parsed, never evaluated. Severity is `medium` for the presence and `high` when the
file both declares an `actions` / `rules` / `postbuilds` key and carries a command line matching
the same `LIFECYCLE_SIGNALS` table A1 grades a lifecycle script by.

**Why Tier A.** The decidable half is the whole finding. npm's default install command for a
package that ships a `binding.gyp` and declares no `install` or `preinstall` script is
`node-gyp rebuild`; the file is at the package root or it is not, and nothing has to be inferred
about any code to know that a build runs. That is the standard A1 and A22 are already read at — a
field npm itself must read literally in order to act on it — rather than the narrower "the harness
reads it", which neither of those satisfies either.

**Why it is worth a check at all, given the base rate.** Install-time execution is off by default
now: pnpm ≥ 10 and npm ≥ 12 block a dependency's lifecycle scripts until the package is named in
`allowBuilds`. That is why §16 keeps `install-lifecycle-script` a `medium` category rather than the
headline signal — and it is the same fact that makes this check worth having. A gate on `scripts`
moves the declaration somewhere that is not `scripts`. `binding.gyp` is one of those places, and
the reason it is the interesting one is that it appears in **no entry point a reader checks**: not
`main`, not `bin`, not `exports`, not `scripts`. It still reaches the same `allowBuilds` prompt,
without needing a key in `package.json` at all. `.vscode/tasks.json` and `.claude/settings.json`
are the same shape of move and are **not** covered here; the catalogue says so rather than implying
a family it does not have.

**Why not parse it.** GYP is Python-ish, not JSON: single-quoted strings, `#` comments, trailing
commas, and `conditions` whose first element is a Python expression written as a string. `node-gyp`
shells out to Python to read it, and there is no maintained JavaScript parser for the format.
Hand-rolling one would put new owned parsing in front of an attacker-controlled file, which the
workspace conventions push against and which is the worst place to take that trade; evaluating a
condition is the one thing this tool may never do at all. And it would not change the verdict:
what separates a build *declaration* from a build *step* is a key name and the shape of the command
under it, and both are literal text in the file either way. So the finding is raised on presence —
which cannot be evaded while the build still happens, which is what keeps `bypass` `null` — and
only the grade reads the command line.

**The extra decidable signal, kept out of the severity.** When the package ships no C-family source
at all, the detail says so: a gyp with nothing to compile is a build declaration whose only effect
is that a build runs. It does not raise the severity, because a target whose sources are missing
fails its build and runs nothing, and a `.cc` the reader skipped for its size still counts as a
source — otherwise the more alarming sentence is decided by what the reader felt like reading.

**Measured cost.** Zero. On the pinned corpus the check fires on none of the 40 packages, and the
re-recorded baseline differs from the previous one in the `tool` field and nothing else.

---

## 22. An escaped identifier is a reporting gap, not a detection gap — measured, not assumed

**Decision.** C8 reports identifiers written with Unicode escapes, at `medium`, and joins C3 in
`NON_DEGRADING_CHECKS`: it does **not** make a Tier B negative unreliable.

**What was actually checked.** The concern was the stronger one: `NETWORK_GLOBALS`,
`DYNAMIC_CODE_CALLEES`, `CREDENTIAL_PATHS` and the rest all match *names*, so an escaped identifier
would defeat every one of them silently. That was established by running it rather than by reading
the parser's documentation. `ts.createSourceFile` over `\u0066etch(…)` returns an `Identifier` whose
`.text` is `fetch`, and over `"node:\u0063hild_process"` a `StringLiteral` whose `.text` is
`node:child_process`: the scanner resolves the escape before any node exists, so there is nothing
downstream that could be keyed on the escaped spelling. The confirming run was the new fixture
against the *pre-change* build, which already reported B6, B7, B8, B9 and B12 on it with every name
escaped.

So the gap was never in detection. It was that the tool said nothing about a file written to be
misread by a person, and a reader comparing the report to the source would have found the report
describing names the file does not appear to contain.

**Why it does not degrade.** Every other Tier C check says the analyzer could not read something,
and that is what makes a Tier B negative worthless. Here the analyzer read exactly what the engine
will run. Degrading on it would mark the package unreadable on the strength of a property the
parser had already neutralised — the same error §7 avoids for C3, in a different shape.

**Why it is still a finding.** Nothing spells a name this way by accident and a published package
has no build reason to, so the file is telling a person something different from what it tells the
engine. `@kolbo/mcp@1.57.1` (GHSA-pm5r-9rq7-j86p) is the shipped instance. `medium`, because the
concealment is real and its effect on this analysis is nil.

**One finding per package**, not per site, with the resolved names in the detail and the count in
`occurrences` — §12 applied: an obfuscator that escapes ninety identifiers warrants the same one
decision the first of them warranted.

---

## 23. A name is folded or the report degrades; a receiver is never followed

**Decision.** A string that selects a target — a module specifier, a seam key, an event name, an
environment variable, a tool `description` — is read through a bounded constant folder in
`src/syntax.ts`: a literal, a `+` chain of them, a template whose spans are literals, or
`[…].join(…)` over an array of them, to a nesting bound of eight. Everything else is refused, and
the refusal raises `C2`. `process.getBuiltinModule(id)` joins `import` and `require` as a way a
module arrives. A member detached from a known receiver — `const { provide } = ctx`,
`const p = ctx.provide`, `function apply({ provide })` — raises `C2` and is **not** resolved.

**What was wrong.** A package spelling all three of these in the unusual way produced no Tier B
finding, no Tier C finding, and `negativesReliable: true`. It was a false clean bill of health,
which is worse than a missed finding because the reader acts on it — the same class as the YAML
alias evasion §18 fixed.

**Why C2 did not fire, which was the actual defect.** C2 was built entirely around a hidden
*name*: a computed member, an assembled argument, a base64 decode. But every Tier B check matches a
member **on a receiver**, so there are two ways to miss, and only one of them was covered. Detach
the member and the name is right there in plain text while the thing Tier B keys on is gone. The
fix is the second half of the same idea, not a special case for `provide.call`.

**Why the receiver is not followed.** Resolving `const { provide } = ctx` to `ctx.provide` and
re-matching B1 at the call site is alias tracking, and the next spellings — a context passed into a
helper, `ctx.provide.bind(ctx)`, a member stored on an object — are behind it with no natural stop.
Every one of them would still need the degrade. So the degrade is the answer, and the detection
would only ever have been an extra.

**Why fold at all, then.** Folding is bounded in a way alias resolution is not: it reads the
expression in front of it and never leaves that expression. `['node:child', '_process'].join('')`
is a name the file states, and a degrade is a worse answer than the `B9` the name earns. The two
tiers call the same function, so a folded site is matched and not degraded, and an unfoldable one
is degraded and not silently dropped — there is no third outcome.

**What still passes silently, and where it is written down.** The heuristics that read *content*
rather than select a target — `B6`'s credential paths, `B10` and `A21`'s injection phrasing, `B8`'s
pair — are missed with no `C2`, because nothing was unreadable: the bytes were read and the rule
did not match. `docs/ceiling.md` says so in those words, because `negativesReliable` had been read
as a promise about all of Tier B and it was never that.

**Measured.** The pinned 40-package corpus produces a byte-identical distribution before and after
— 295 findings, 3 critical, 80 high, median 5.5, 21 of 40 carrying a high or critical. None of the
three spellings appears in a legitimate published plugin, which is the reason to report them.

---

## 24. Provenance is a fact; the report separates what npm asserted from what was checked

**Decision.** `--from-npm` reads npm's build provenance attestation when the version document says
there is one, and emits it as a **Fact** in five states — `unavailable` for a directory or local
tarball, `absent`, `unreadable`, `attested`, `failed`. Four checks run offline against bytes already
in hand: the statement's subject digest is the SHA-512 of the downloaded tarball, the subject is
this package at this version, the DSSE signature verifies under the certificate carried in the
bundle, and that certificate's subject alternative name is the workflow the statement claims. Two
things are **not** established and are printed in the same block every time the four are:
`certificate-chain` — that the certificate is Sigstore's — and `transparency-log`. Only a `failed`
state raises a finding (`A25`, high).

**Why absence raises nothing.** Measured before deciding: of the 40 packages in the pinned corpus,
**12 publish a provenance attestation and 28 do not**. A finding on the 70 % would be a finding
about the ecosystem rather than about a package, which is precisely the miscalibration §17 and the
0.2 release exist to prevent. So absence is a fact with no severity, and the fact's own text says
that most published packages are in that state.

**What A25 therefore is, and is not.** It is not an attack detector: a publisher who wants no
provenance publishes none, and that is silent. Nothing about the check can be *made* to fail by an
attacker who would otherwise be caught. What it catches is an attestation that exists and does not
describe the artifact it was served with — the wrong version's bundle, a mirror that mismatched
them, a payload edited after signing. That is a defect however it arose, and it is worse than no
attestation, because a reader who saw only the badge would conclude the opposite.

**Why the verification stops where it does.** The bundle is a Sigstore bundle, and full
verification is a chain: the leaf certificate must chain to the Fulcio root, and the Rekor entry
must be checked against Rekor's key. Both roots live in the Sigstore trust root, which is served by
`tuf-repo-cdn.sigstore.dev` — a **different host**, which `SECURITY.md` forbids reaching. Pinning
them as constants instead is a trust-root decision, not an implementation detail, and it is left to
the maintainer rather than made here. What is left is genuine but narrower: the four checks prove
the bundle is internally consistent and is about these exact bytes. The digest check is the
load-bearing one — it is the link that makes one chain of digests run from `dist.integrity` through
the download into the signed statement — and it is why `readProvenance` takes the verified tarball
rather than trusting the statement's own account of what it covers.

**Why the endpoint is built and not followed.** `dist.attestations.url` is ignored. The tarball URL
has to be read out of the packument because there is no other way to name it, which is why it is
guarded by an origin check; an attestation needs no such freedom, so the URL is constructed from
the `--registry` base and the resolved name and version, and those two are re-validated against the
same patterns `parseSpec` uses because both come out of a registry-controlled document. A doctored
packument cannot redirect the request at all, not even to another path on the same host.

**Why a provenance failure never fails the analysis.** The tarball has already been checked against
`dist.integrity` by the time the attestation is read. An endpoint that is down or a bundle that does
not decode leaves the fact `unreadable` — a third answer, distinct from `absent` — and the report
is produced. Turning a registry outage into exit code 2 would make provenance a precondition for
reading a package rather than something reported about it.

**What the fixture proves by being what it is.** `tests/support/attestation-fixture.ts` issues its
own **self-signed** certificate and signs its own statements. That is possible only because no
chain is validated, and it is the documented limit demonstrated rather than described: a
certificate nobody issued passes every check this tool runs, which is why the `not checked` block
is printed and not footnoted.

**Measured.** The pinned 40-package corpus produces the same distribution as before — a Fact moves
no number, and `A25` fires on none of the 40.

---

## 24. Composition checks: what a package does to somebody else's profile

**Decision.** Four checks — A26, B14, B15, B16 — grade a package by how it composes into a profile
that already holds other people's plugins, rather than by what it declares about itself.

**Why.** The catalogue up to `0.7.0` graded declarations (Tier A) and capabilities (Tier B), and a
hostile package that used neither passed clean. Three such packages are in `tests/fixtures/` and
each was verified to produce **no findings at all** before the check that catches it was written:

- `approval-autoanswer/` answers `approval/request` itself and allows every `tools/pre-execute`,
  by not calling `next`. No row is disabled, no seam is provided, no credential, socket, process
  or file is touched.
- `guard-eviction/` performs the substitution B1 exists for, without `provide` or `set`: it writes
  a member of `ctx.subprocess`, clears the map behind `ctx.tools.guard()`, splices the listener
  table, and calls `ctx.registry.delete` on another plugin.
- `foreign-row-hijack/` disables one plugin's row and rewrites another's `config` by id.

**What was verified rather than assumed.** Every mechanism was executed or read in the installed
build, not inferred:

- `waterfall` was read at `@deepseek-ai/cordis@4.0.2` `lib/index.js:317-327`, and the widely
  repeated claim that skipping `next()` *deletes* the listeners behind it is **false**. `dispatch`
  hands back a fresh array (`.filter(...).map(...)`), `next()` shifts that copy, and `_hooks` is
  untouched. The veto lasts one dispatch. Removal is a separate capability, and it is B16's.
- Service mutability was checked by running the installed Cordis: a member written through one
  plugin's context is what the root context reads afterwards, and the service is not frozen.
  Assigning the *whole* service from a foreign fiber throws `cannot set property "approval" in
  multiple fibers`, so B15 grades member writes and deliberately not that.
- What each decision waterfall's built-in `next` settles on was read at its dispatch site:
  `dsh-tools/lib/index.js:3117` (`{kind:'allow'}`), `:3214` (**the tool body itself**), and
  `dsh-user-approval/lib/index.js:179` (`"unavailable"`, reached only after every answerer).

**The false-positive line, which is where the design actually happened.** Two shapes were rejected
for firing on honest code:

- *Prepending on a decision seam* is not a check. `dsh-dlp` prepends at three seams on purpose,
  and `{prepend: true}` is how a security plugin gets ahead of the chain. It is reported inside
  B14's detail instead, where it only ever describes a listener that is already vetoing.
- *Reading `ctx.events._hooks`* is not a check. `dsh-dlp/src/approval-reach.ts:114` counts the
  composed answerers to decide whether an approval would reach a human. B16 raises only a write to
  that table.

Measured after the fact: **zero** A26/B14/B15/B16 findings across `dsh-dlp`, `dsh-netguard`,
`dsh-ocsf-forwarder`, this package, and all **224** `@deepseek-ai/*` packages in the installed
harness — a corpus that contains 41 waterfall listener registrations across ten of the thirteen
event names, including one on `approval/request` and three on `tools/pre-execute`. The check
examined each and passed it, so the zero is discrimination and not an empty sweep.

**Not measured.** A26 has not been run against the forty-package published corpus `pnpm run sweep`
pins, because that needs a network and is not part of CI. Nothing in that corpus is expected to
ship a `dsh.bundle.patch` that overrides a row, but that is a prediction, not a measurement, and
the severity should be treated as provisional until the sweep confirms it.
