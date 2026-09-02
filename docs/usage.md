---
title: Usage
nav_order: 3
---

# Usage

[← dsh-plugin-inspector docs](index.md)

```
dsh-inspect <target> [options]
dsh-inspect --from-npm <name>[@<version>] [options]

  <target>                A plugin directory, or an npm tarball (.tgz / .tar.gz).

Options
  --from-npm <spec>       Fetch a published package from the registry, verify its
                          dist.integrity hash, read its provenance attestation
                          if it has one, and analyse it in memory.
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

### Provenance, and the line between a claim and a check

When the version document says the version has an npm **provenance attestation**, `--from-npm`
makes one more request — to `<registry>/-/npm/v1/attestations/<name>@<version>`, on the registry
you gave it — and reports the source repository, commit, ref and workflow the signed statement
names. Most published packages have none; 28 of the 40 in the pinned corpus do, so an absence is
reported as a fact and raises nothing.

The report is explicit about which half you are reading. It prints a `checked` block — the
statement covers the exact bytes that were downloaded, it is about this package at this version,
its DSSE signature verifies under the certificate in the bundle, and that certificate names the
workflow the statement claims — and, always alongside it, a `not checked` block: **this tool
carries no Sigstore trust root**, so it does not establish that the certificate is Fulcio's or
check the Rekor inclusion proof. A registry serving a doctored bundle passes everything above. See
[the check catalogue](checks.html#what-the-provenance-fact-says-and-what-it-does-not) for what
provenance does not prove even when it is fully verified.

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
