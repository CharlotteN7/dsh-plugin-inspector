# Security policy

## Reporting a vulnerability

Email **nsof@protonmail.com**. Please do not open a public issue first.

Include the target that triggered the problem — a package directory or a `.tgz` — or a recipe for
building one, plus the command line and the output you got. A tarball attached to the mail is
ideal; this tool never installs, builds, or runs the package it is pointed at, so sending one is
safe to receive.

Expect an acknowledgement within a week.

## What counts as a vulnerability in this tool

`dsh-inspect` reads untrusted packages, so its own attack surface is the reading. The following are
security bugs and are treated as such:

- **Execution of anything from the analysed package.** Nothing in a target may be imported,
  required, spawned, or evaluated. The `!!js` expressions in a patch layer are parsed and compiled
  to check that they parse; the result is discarded without being called. A path from an analysed
  package to a running instruction is the most serious bug this project can have.
- **A write anywhere on the filesystem** as a result of analysing a target. Tarballs are decoded
  entirely in memory and no extraction call exists in the source.
- **A network request that was not asked for.** `--from-npm` is the only mode that opens a socket
  and it is one explicit flag per invocation. A directory or tarball scan reaching the network is a
  security bug. `--from-npm` reaching a host other than the registry it was given is one too, and
  it is already refused rather than merely disallowed: `resolvePackage` compares the packument's
  `dist.tarball` origin against the registry base URL and throws before any download, so a single
  doctored packument on an honest registry cannot make this tool fetch an arbitrary URL. A build
  where that refusal is missing is the bug.
- **Analysing bytes whose hash does not match what the registry published.** On the `--from-npm`
  path `dist.integrity` is verified before any byte reaches the parser. A mismatch that produces a
  report instead of a refusal is a security bug.
- **Unbounded resource use** from a crafted target: memory, time, or recursion. A hostile archive
  or a YAML layer built out of aliases must produce a finding or a clean refusal, never a hang and
  never an out-of-memory kill.
- **A wrong exit code.** `0`, `1`, and `2` are a CI contract. A crash that leaves 1 — the code that
  means "findings at or above `--fail-on`" — is a bug, because a job then reads a broken analyzer
  as a verdict about the package.
- **A `certain`-confidence Tier A finding that is false.** Tier A claims to read a declaration the
  same way the harness reads it. A finding that misstates what the harness does with a field is a
  correctness bug in the one part of the tool that issues verdicts.

## What does not count

- **A missed capability in Tier B.** Every Tier B check is a shape match on one AST node and every
  one of them carries its own bypass in the finding. Defeating one is expected and documented; it
  is why a Tier C hit forbids the report from claiming a clean negative.
- **A prompt-injection phrase the heuristics do not match.** These are heuristics over natural
  language and the findings say so. Homoglyph substitution — a Cyrillic `о` for a Latin `o` —
  defeats every rule in the table, is known, and is recorded in [`docs/ceiling.md`](docs/ceiling.md)
  §8.
- **A finding about a package you consider benign.** Tier B reports capability, not intent. Please
  do open a normal issue if a check fires on ordinary code — a false positive is a real defect —
  but it is not a security report.

## Scope of the tool itself

This is static pre-install triage. It does not run in the harness process, does not gate
installation, and cannot stop anything. It reads one version of one package: not its transitive
dependencies, not code fetched at runtime, and not a later version that gains a `dsh.bundle`
declaration and is mounted by the next `dsh plugin update`.
