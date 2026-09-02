---
title: The ceiling
nav_order: 5
---

# The ceiling

[← dsh-plugin-inspector docs](index.md)

**This is triage. It is not containment.**

The tool does not run in the harness process, does not gate installation, and cannot stop
anything. It raises the cost of shipping a hostile plugin and gives you something to read where
today you see nothing. That is the whole claim.

A seam at which an install *could* be stopped does exist — `dsh plugin add` runs pnpm in the
profile directory, pnpm honours a `.pnpmfile.cjs` there, and throwing from its async `readPackage`
hook aborts the install with nothing written to `node_modules`. Nothing in 0.5 uses it.
[`ADR.md`](https://github.com/CharlotteN7/dsh-plugin-inspector/blob/main/ADR.md) §11 records the
seam and why shipping a gate on this release's calibration would have burned the idea. The link
leaves the site on purpose: Pages builds from `docs/` alone, so a relative link to a file at the
repository root is a 404 on the published page.

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
7. **What a YAML alias makes the file mean.** An anchored node is one node, and every `*alias` to
   it is that same node again in a second position. The reader expands each occurrence to its own
   node so the layer is analysed the way the loader composes it, but the file a reviewer reads and
   the layer that mounts are then two different documents, and the expansion is bounded — past the
   node or nesting ceiling the rest is unread. Any layer using an anchor raises `C7`, which
   degrades the analysis; a clean report over an aliased layer is not a claim that the layer is
   clean.
8. **A constant this tool cannot fold.** A name selecting a service, a module or an event is
   resolved when it is a literal, a `+` chain of literals, a template whose spans are literals, or
   `[…].join(…)` over literals — and refused for everything else, including a module-scope `const`
   bound to one of those and used a line later. Refusing is deliberate: resolving a binding is
   value tracking, and every attempt to reach a little further has a next case behind it. The
   refusal is not silent — it is `C2`, and it degrades the report.
9. **Which implementation a detached member reaches.** `const { provide } = ctx` and
   `const p = ctx.provide` leave a bare name that still does everything `ctx.provide` does, and no
   Tier B check matches it, because they all match on the receiver. This tool reports the
   detachment rather than following it, so the outcome is a degraded report and not a `B1`. The
   same is true of a context passed into a helper, or `ctx.provide.bind(ctx)` — neither is
   detected, and **neither degrades the report either**, which is the sharpest remaining hole in
   this tier.
10. **Injection phrasing that is not spelled in ASCII.** The injection heuristics are Latin-alphabet
   regexes. Substituting Cyrillic homoglyphs — `о` U+043E for `o`, `е` U+0435 for `e` — defeats
   **every one of the eleven rules**, including the two hidden-character rules, which look for
   invisible characters and not for visible ones that are the wrong letter. Verified against the
   rule table, not assumed. Normalisation is not in 0.5; do not read a clean `A21`/`B10` as
   evidence that shipped markdown carries no instructions.

### Every Tier B check has a one-line bypass, and not every bypass is visible

`ctx['pro' + 'vide']('approval', …)` defeats seam detection. A computed specifier defeats every
import check. A base64 event name defeats every listener check. Splitting a credential read and a
network call across two packages defeats `B8`. A Cyrillic `о` defeats every injection rule.

Those bypasses do not all cost the same. **A name that selects a target either folds to a constant
this tool can read, or raises `C2` and degrades the report** — that covers a computed member on
`ctx`, a specifier this tool cannot fold, a name assembled at runtime, a `base64` decode, and an
API method pulled off its receiver and called through a bare binding. There is no way to hide
*which* service, module, or event is being reached that leaves the report claiming its negatives
are reliable.

**The heuristics that read content rather than select a target are the other half, and they are
silent.** `B6` matches a credential path written as one string, so a path split across a
concatenation the folder does not reach is missed with no `C2`. `B10` and `A21` match English
phrasing, so a homoglyph or a rephrasing is missed with no `C2`. `B8` is a pair, so splitting the
halves across two packages is missed with no `C2`. Nothing degrades in any of those cases, because
nothing was unreadable: the tool read the bytes and its rule did not match them. **So a clean
`B6`, `B10`, `A21` or `B8` is not a claim, whatever `analysis.integrity` says.** `negativesReliable`
is a statement about whether the analyser could resolve the names it matches on — not a promise
that a heuristic caught what it was looking for.

Three spellings that used to cost nothing at all now cost a finding or a degrade, and the fixture
`tests/fixtures/detached-dispatch/` is the record: `process.getBuiltinModule('node:fs')` reaches a
builtin with no import declaration and is now read as one, a specifier assembled out of string
literals is folded and matched, and `const { provide } = ctx` followed by
`provide.call(ctx, 'approval', …)` raises `C2` because the receiver every Tier B check matches on
is gone.

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
