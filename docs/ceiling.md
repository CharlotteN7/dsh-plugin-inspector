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
8. **Injection phrasing that is not spelled in ASCII.** The injection heuristics are Latin-alphabet
   regexes. Substituting Cyrillic homoglyphs — `о` U+043E for `o`, `е` U+0435 for `e` — defeats
   **every one of the eleven rules**, including the two hidden-character rules, which look for
   invisible characters and not for visible ones that are the wrong letter. Verified against the
   rule table, not assumed. Normalisation is not in 0.5; do not read a clean `A21`/`B10` as
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
