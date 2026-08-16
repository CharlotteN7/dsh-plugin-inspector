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
2. There is no seam to gate. `runPlugin()` in `dsh/apps/cli/src/plugin.ts` is
   `spawnSync('pnpm', args)` followed by a manifest rewrite — 158 lines, read end to end. There is
   no event, no approval hook, and no confirmation prompt anywhere in the path. A mounted
   inspector would have to poll or wrap the binary, which is worse than a CLI in every respect.
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

**Why.** These are facts about harness version `0.1.0-rc.6`, not opinions, and they will go stale.
Keeping them in one module makes re-syncing against a new harness a single reviewable diff rather
than an archaeology exercise across a dozen check functions. `HARNESS_REFERENCE` records which
version they came from.

The row id → module name map is transcribed from the three shipped bundle patches rather than
hand-typed, because the `name` half is load-bearing: `applyEntryPatches` treats `name` on a
non-insert patch as an assertion guard, so a patch naming the wrong module is silently skipped
in full. Check A4 exists only because that map does.

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

**Honesty note carried in the findings.** These are heuristics over natural language. They will
miss a rephrasing and they can fire on a document that legitimately discusses the subject. Every
B10 finding names which rule matched so the reader can judge it.

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

**Decision.** `vitest.config.ts` carries the measured numbers (91 % statements, 95 % lines,
96 % functions, 81 % branches) rather than the 100 % per-file bar this workspace adopts for
security code.

**Why.** A gate that fails on every run is not a gate; it is noise that gets removed. Holding the
measured numbers means a regression fails CI today, and the ratchet moves up as the remaining
branches get tests of their own. What matters more than the number is *which* lines are covered:
the resource ceilings, the symlink and escaping-entry refusals, and every check in the catalogue
now have a case, because those are the lines that carry the safety claims. The comment in the
config says exactly this so the number is not mistaken for the target.
