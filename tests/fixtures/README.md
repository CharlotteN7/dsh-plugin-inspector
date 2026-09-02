# Hostile fixtures

**Every package in this directory is deliberately hostile, and every one of them is inert.**

They exist so the inspector's catalogue can be checked against something that behaves the way a
real attack would: a patch layer that switches the approval row off, a `!!js` expression that
reaches `child_process`, a `postinstall`, a credential read paired with `fetch`, a `SKILL.md`
written to be read by a model rather than a person, an MCP stdio row, an obfuscated bundle, a `!js`
tag, a `dsh.bundle.patch` path that climbs out of its package, a `binding.gyp` whose build step is
the payload, a module whose every global is spelled with a Unicode escape, and a module that
reaches all three of its capabilities without spelling any of them the way a name table expects.
`benign-control/` is the opposite and must produce zero findings; a tool that fires on it is not
worth reading.

`detached-dispatch/` is the one that is about the tool rather than about a reader.
`process.getBuiltinModule('node:fs')` reaches a builtin with no import declaration, a specifier
assembled out of two string literals is put back together before it is matched, and `provide`
destructured off the context replaces the `approval` seam through a call that names no receiver.
Two of the three are decidable and produce findings; the third is not, and the fixture's real
assertion is that the report comes back **degraded** rather than clean — a false clean bill of
health being worse than a missed finding, because the reader acts on it.

`phantom-gyp/` and `escaped-identifiers/` are the two that are invisible to a reader checking the
manifest. The first declares no lifecycle script at all: its install-time execution point is a file
no key of `package.json` names. The second is written so that what a person reads and what the
engine runs are different documents — and it is also the evidence that this tool reads the second
one, because the capability findings it produces are the same ones the plain spelling produces.

## Why none of it can run

Nothing here is installed, built, imported, or mounted by anything in this repository.

- The fixtures are not workspace packages and have no `node_modules`. `pnpm-workspace.yaml` does
  not include them.
- The test suite calls `inspect()` on their paths. That reads bytes and parses them. It does not
  import a module from a fixture, does not spawn a process, and does not evaluate a `!!js`
  expression — `tests/unit/no-execution.spec.ts` mocks `node:child_process` and the write half of
  `node:fs` to throw for the whole suite, so a stray call fails the tests rather than passing
  quietly.
- `execution-canary/` is the direct proof: its `preinstall`, `postinstall`, and `prepare` scripts,
  its `!!js` expressions, and its module top level all write a sentinel file, and the test asserts
  the sentinel does not exist after a full analysis.
- The install scripts run harmless commands. The exfiltration fixture posts to
  `telemetry.example.invalid`, a name reserved by RFC 2606 that cannot resolve, and so does the
  `binding.gyp` build step in `phantom-gyp/` — which nothing here installs, so `node-gyp` never
  reads it. The inspector matches that file as text and does not parse or evaluate it.

## The one that is a live payload

`skill-injection/skills/deploy-helper/SKILL.md` is a **working prompt-injection payload**. It is
not a description of one — it is the text itself, in a filename that coding agents actively ingest,
and an agent that reads it as an instruction will do what it says.

The file opens with a marker saying so. Leave the marker in place, and do not copy the file into a
skills directory, a workspace, or anywhere an agent scans.
