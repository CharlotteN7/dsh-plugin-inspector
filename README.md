# dsh-plugin-inspector

**Know what a plugin does before you install it.**

`dsh-inspect` reads a DeepSeek Harness plugin — a directory, an npm tarball, or a published package
fetched by name and checked against the hash the registry published — and tells you what it
declares and what its code is capable of. It does not install it, build it, import it, spawn it, or
evaluate any part of it.

```console
$ dsh-inspect --from-npm some-dsh-plugin@1.4.0
```

📖 **[Full documentation](https://charlotten7.github.io/dsh-plugin-inspector/)**

## Why

`dsh plugin add` is a thin pnpm forwarder: it passes your arguments to pnpm verbatim, and a plugin
is ordinary Node code that runs in the agent's process at the agent's uid. Nothing between the
registry and that process tells you what the code can reach.

[The full argument →](https://charlotten7.github.io/dsh-plugin-inspector/)

## Install

Node `^22.19.0 || >=24`.

```console
npm install -g dsh-plugin-inspector
dsh-inspect --help
```

From a checkout instead — `lib/` is generated, so a fresh clone has no `dsh-inspect` until built:

```console
git clone https://github.com/CharlotteN7/dsh-plugin-inspector
cd dsh-plugin-inspector
pnpm install && pnpm run build
node lib/cli.js --help
```

## Usage

```
dsh-inspect <target> [options]
dsh-inspect --from-npm <name>[@<version>] [options]

  --from-npm <spec>       Fetch from the registry, verify dist.integrity, analyse in memory.
  --registry <url>        Registry base URL for --from-npm.
  --json                  Emit the machine-readable JSON document on stdout.
  --fail-on <severity>    Exit 1 at or above this severity.  (default: high)
  --no-color              Plain text, no ANSI.
```

**Exit codes are the CI contract:**

| Code | Meaning |
|---|---|
| `0` | Analysis completed; nothing at or above `--fail-on` |
| `1` | Analysis completed; at least one finding at or above `--fail-on` |
| `2` | Analysis could not be performed |

`2` is deliberately distinct from `1`. A job that cannot tell "the analyzer broke" from "the plugin
is clean" is the failure this split exists to prevent.

[Full usage, and getting a package without installing it →](https://charlotten7.github.io/dsh-plugin-inspector/usage.html)

## What it looks for

Findings are tiered by how much you should trust them:

| Tier | What it means |
|---|---|
| **Facts** | No severity, always emitted — what the package declares about itself |
| **Tier A** | Decidable from a structured declaration. A real verdict. |
| **Tier B** | AST capability detection — "this plugin *can* do X" |
| **Tier C** | Heuristic; "we cannot read this" is itself the finding |

[Every check, by tier →](https://charlotten7.github.io/dsh-plugin-inspector/checks.html)

## The ceiling

**This is not a malware scanner and it cannot be one.** Capability is decidable from source;
intent is not. Every Tier B check has a one-line bypass, and the tool says so per finding rather
than implying a completeness it does not have. What it does guarantee is that it never runs the
code it analyses — asserted from outside the unit suite by a CI canary whose fixture writes
sentinel files from `preinstall`, `postinstall`, `prepare`, `!!js` config and module top level. Any
sentinel on disk after a full analysis is a release blocker.

[What is not statically decidable →](https://charlotten7.github.io/dsh-plugin-inspector/ceiling.html) ·
[What it reports on the real ecosystem →](https://charlotten7.github.io/dsh-plugin-inspector/ecosystem.html)

## Development

```sh
nvm use 22           # Node ^22.19.0 || >=24, and pnpm 11
pnpm install
pnpm run typecheck
pnpm run test:coverage
pnpm run test:e2e
```

Severity calibration is pinned against a corpus of published packages, so a change that starts
firing on ordinary code fails CI rather than shipping.

Design decisions and their rationale live in [ADR.md](ADR.md). Security policy is in
[SECURITY.md](SECURITY.md).

## License

MIT
