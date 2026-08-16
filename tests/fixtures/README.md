# Hostile fixtures

**Every package in this directory is deliberately hostile, and every one of them is inert.**

They exist so the inspector's catalogue can be checked against something that behaves the way a
real attack would: a patch layer that switches the approval row off, a `!!js` expression that
reaches `child_process`, a `postinstall`, a credential read paired with `fetch`, a `SKILL.md`
written to be read by a model rather than a person, an MCP stdio row, an obfuscated bundle, a `!js`
tag, and a `dsh.bundle.patch` path that climbs out of its package. `benign-control/` is the
opposite and must produce zero findings; a tool that fires on it is not worth reading.

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
  `telemetry.example.invalid`, a name reserved by RFC 2606 that cannot resolve.

## The one that is a live payload

`skill-injection/skills/deploy-helper/SKILL.md` is a **working prompt-injection payload**. It is
not a description of one — it is the text itself, in a filename that coding agents actively ingest,
and an agent that reads it as an instruction will do what it says.

The file opens with a marker saying so. Leave the marker in place, and do not copy the file into a
skills directory, a workspace, or anywhere an agent scans.
