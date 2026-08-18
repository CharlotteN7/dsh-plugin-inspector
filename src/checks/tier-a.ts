/**
 * Tier A — decidable checks over structured declarations.
 *
 * Everything here reads a field the harness itself must read literally in order
 * to act on it: a `package.json` key, or a Cordis patch row. That is why Tier A
 * findings carry `certain` confidence and why they are the only findings this
 * tool treats as verdicts. `disabled: true` cannot be obfuscated and still
 * disable anything.
 * @module dsh-plugin-inspector/checks/tier-a
 */

import { isJsExpr, type ExpressionClass, type ExpressionSite } from '../cordis-yaml.ts'
import { boundedJson, isNativeSource, lineColumn, normalizePackagePath, snippet } from '../files.ts'
import { scanInjection } from '../injection.ts'
import {
  CORE_ROWS,
  GYP_COMMAND_KEYS,
  HARNESS_BUNDLE_PACKAGES,
  INSTALL_LIFECYCLE_SCRIPTS,
  MCP_CLIENT_PACKAGE,
  NATIVE_BUILD_FILE,
  SECURITY_ROW_IDS,
  SECURITY_SEAM_KEYS,
  SEAM_KEYS,
  SKILL_FILESYSTEM_ROW,
  SKILL_ROOT_CONFIG_KEYS,
  matchingLifecycleSignals,
} from '../knowledge.ts'
import { declaredPackages } from '../manifest.ts'
import type { Finding, Severity } from '../model.ts'
import type { CheckInput } from './input.ts'

/**
 * Checks that read a Cordis patch row. None of them may produce a finding
 * about a package the harness never composes into a profile: `dsh plugin add`
 * on a package with no `dsh.bundle` installs a plain library and says so, and
 * whatever YAML that library happens to ship is inert bytes.
 */
const PATCH_ROW_CHECKS: ReadonlySet<string> = new Set([
  'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10', 'A15', 'A17', 'A19', 'A23',
])

/** Loader builtins that are entry names but not resolvable npm packages. */
const LOADER_BUILTINS: ReadonlySet<string> = new Set([
  'cordis:include', 'cordis:group',
  '@deepseek-ai/cordis-plugin-group', '@deepseek-ai/cordis-plugin-include',
])

/** Specifier prefixes that do not pin an immutable registry artifact. */
const MUTABLE_SPECIFIER = /^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:)/

/**
 * How much reach each `!!js` classification represents.
 *
 * `call` is medium, not high: the class means "calls something this tool
 * cannot resolve", and under `with (ctx)` most of what a config expression can
 * call is a service the profile already handed it. `harness-call` is lower
 * still — the harness itself puts those functions in scope.
 */
const EXPRESSION_SEVERITY: Readonly<Record<ExpressionClass, Severity>> = {
  'module-access': 'critical',
  mutation: 'high',
  call: 'medium',
  unparseable: 'medium',
  'harness-call': 'low',
  'inert-read': 'low',
  literal: 'low',
}

/** What each `!!js` classification means, in one clause. */
const EXPRESSION_MEANING: Readonly<Record<ExpressionClass, string>> = {
  'module-access': 'reaches the module system, the global object, or the evaluator',
  mutation: 'writes to something rather than only reading',
  call: 'calls something this tool cannot resolve',
  unparseable: 'does not parse, so the entry cannot mount',
  'harness-call': 'calls a helper the harness provides to config expressions',
  'inert-read': 'reads an identifier',
  literal: 'is a constant',
}

/**
 * Classifications with no reach at all. A constant and a read of a service the
 * profile already provides are what the shipped bundles are made of, so they
 * are counted as a fact and never raised as a finding.
 */
const INERT_CLASSES: ReadonlySet<ExpressionClass> = new Set<ExpressionClass>(['literal', 'inert-read'])

/**
 * Build one finding, keeping every Tier A finding at `certain` confidence and
 * `null` bypass — a structured declaration has no syntactic evasion.
 * @param finding - everything but the fixed fields.
 * @returns the complete finding.
 */
function tierA(finding: Omit<Finding, 'tier' | 'confidence' | 'bypass' | 'examples' | 'occurrences'>): Finding {
  return { ...finding, tier: 'A', confidence: 'certain', bypass: null, examples: [finding.evidence], occurrences: 1 }
}

/**
 * Whether the package under analysis is itself one of the harness's shipped
 * bundles. A bundle composes the core row set: `@deepseek-ai/dsh-web-app`
 * disabling two dozen rows `@deepseek-ai/dsh-base` inserted is what a bundle
 * *is*, and reporting each one as an attack on the profile says nothing.
 * @param input - the decoded package.
 * @returns true when this package's own name is a shipped bundle's.
 */
function isHarnessBundle(input: CheckInput): boolean {
  return HARNESS_BUNDLE_PACKAGES.has(input.manifest.name)
}

/**
 * How severe it is to remove one core row, by which bundles define it. Every
 * profile mounts `base`; `headless` and `web-app` are surface bundles a given
 * profile may never have mounted, so a row only they define was never there to
 * lose.
 * @param id - the row id.
 * @returns the severity, or `null` when the id is not a core row at all.
 */
function coreRowSeverity(id: string): Severity | null {
  const row = CORE_ROWS.get(id)
  if (row === undefined) return null
  return row.bundles.includes('base') ? 'high' : 'medium'
}

/**
 * Name the bundles a core row comes from, for a finding's prose.
 * @param id - the row id.
 * @returns a phrase naming the bundles.
 */
function coreRowOrigin(id: string): string {
  const row = CORE_ROWS.get(id)
  /* v8 ignore next -- only called once `coreRowSeverity` has found the id in the same map. */
  if (row === undefined) return 'a shipped bundle'
  return row.bundles.map(bundle => `@deepseek-ai/dsh-${bundle}`).join(' and ')
}

/** A2, A3, A19 — a patch layer switching a core row off, or back on. */
function checkDisabledRows(input: CheckInput): Finding[] {
  if (isHarnessBundle(input)) return []
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const override of patch.overrides) {
      if (override.disabled === undefined) continue
      const expression = isJsExpr(override.disabled) ? override.disabled.__jsExpr : null
      const shown = expression === null ? boundedJson(override.disabled) : `!!js ${expression}`
      // The loader coerces: `disabledOf` is `Boolean(options.disabled)`
      // (vendor/loader/src/config/entry.ts). `null`, `0` and `""` therefore
      // leave the row running, and reporting them as a disabled row would be
      // confidently wrong about the one thing Tier A claims to be certain of.
      // An expression node is an object, so it stays truthy here and is judged
      // by what it can evaluate to rather than by its own shape.
      if (!override.disabled) {
        const enabled = coreRowSeverity(override.id)
        if (enabled === null) continue
        findings.push(tierA({
          checkId: 'A19',
          name: 'core-row-force-enabled',
          subject: override.id,
          severity: 'medium',
          title: `Patch layer re-enables the core row "${override.id}"`,
          detail: 'The loader coerces `disabled` with `Boolean()`, so this value leaves the row running. Because '
            + 'bundle layers apply after the profile\'s own, a row the user deliberately switched off in their '
            + 'personal layer is switched back on by this one — and the user\'s file still reads `disabled: true`.',
          evidence: { file: patch.file, path: `${override.path}.disabled`, snippet: snippet(shown) },
        }))
        continue
      }
      const stops = SECURITY_ROW_IDS.get(override.id)
      if (stops !== undefined) {
        findings.push(tierA({
          checkId: 'A2',
          name: 'security-row-disabled',
          subject: override.id,
          severity: 'critical',
          title: `Patch layer disables the core row "${override.id}"`,
          detail: `Bundle patches apply after @deepseek-ai/dsh-base, so this layer switches off ${stops}. `
            + (expression === null
              ? 'The row stops running for every session in the profile.'
              : 'The expression is re-evaluated at every mount decision, so the row can be switched off conditionally at runtime.'),
          evidence: { file: patch.file, path: `${override.path}.disabled`, snippet: snippet(shown) },
        }))
        continue
      }
      const severity = coreRowSeverity(override.id)
      if (severity === null) continue
      findings.push(tierA({
        checkId: 'A3',
        name: 'core-row-disabled',
        subject: override.id,
        severity,
        title: `Patch layer disables the core row "${override.id}"`,
        detail: `The row comes from ${coreRowOrigin(override.id)}, and this layer applies after it, so the row `
          + 'stops running for every session in the profile.'
          + (severity === 'medium'
            ? ' That bundle is a surface bundle rather than the shared base, so a profile that does not mount it '
              + 'never had this row.'
            : ''),
        evidence: { file: patch.file, path: `${override.path}.disabled`, snippet: snippet(shown) },
      }))
    }
  }
  return findings
}

/** A4, A5 — a patch layer rewriting a core row it did not define. */
function checkOverriddenRows(input: CheckInput): Finding[] {
  if (isHarnessBundle(input)) return []
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const override of patch.overrides) {
      const coreName = CORE_ROWS.get(override.id)?.module
      if (coreName === undefined) continue
      if (override.nameGuard !== null && override.nameGuard !== coreName) {
        findings.push(tierA({
          checkId: 'A4',
          name: 'patch-name-guard-mismatch',
          subject: override.id,
          severity: 'medium',
          title: `Patch for "${override.id}" names ${override.nameGuard}, but that row is ${coreName}`,
          detail: 'applyEntryPatches treats `name` on a non-insert patch as an assertion guard: on mismatch it '
            + 'warns and skips the whole patch. Every override in this patch therefore does nothing, so what the '
            + 'file says and what mounts disagree.',
          evidence: { file: patch.file, path: `${override.path}.name`, snippet: snippet(override.nameGuard) },
        }))
        continue
      }
      const rewritten = override.overriddenKeys.filter(key => key !== 'disabled')
      if (rewritten.length === 0) continue
      const provides = SECURITY_ROW_IDS.get(override.id)
      findings.push(tierA({
        checkId: 'A5',
        name: 'core-row-overridden',
        subject: `${override.id}:${rewritten.join(',')}`,
        severity: provides === undefined ? 'medium' : 'high',
        title: `Patch layer rewrites ${rewritten.map(key => `\`${key}\``).join(', ')} on the core row "${override.id}"`,
        detail: `The row is ${coreName}. Patch overrides are shallow whole-value replacements, not merges, so `
          + `overriding \`config\` discards that row's entire shipped configuration rather than adding to it.`
          + (provides === undefined ? '' : ` This row provides ${provides}.`),
        evidence: { file: patch.file, path: override.path, snippet: snippet(rewritten.join(', ')) },
      }))
    }
  }
  return findings
}

/**
 * A6, A7 — the `!!js` expressions with reach. The complete inventory is a fact
 * (`facts.jsExpressions`); an expression that is a constant or a read of a
 * service the profile already provides warrants no decision and is not raised.
 */
function checkExpressions(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const site of patch.expressions) {
      if (site.slot === 'inert') {
        findings.push(inertExpression(patch.file, site))
        continue
      }
      if (INERT_CLASSES.has(site.classification)) continue
      findings.push(liveExpression(patch.file, site))
    }
  }
  return findings
}

/**
 * One `!!js` node the loader will evaluate.
 * @param file - package-relative YAML path.
 * @param site - the expression site.
 * @returns the finding.
 */
function liveExpression(file: string, site: ExpressionSite): Finding {
  const where = site.slot === 'disabled'
    ? 'A `disabled` expression is re-evaluated at every mount decision, and user patch layers HMR-reload live'
    : 'A `config` expression is evaluated whenever the entry activates or reloads'
  return tierA({
    checkId: 'A6',
    name: 'js-expression',
    subject: `${site.slot}:${site.classification}`,
    severity: EXPRESSION_SEVERITY[site.classification],
    title: `\`!!js\` expression in a row's \`${site.slot}\` ${EXPRESSION_MEANING[site.classification]}`,
    detail: `The loader evaluates this with new Function('ctx', 'expr', 'with (ctx) { return eval(expr) }') — `
      + `unrestricted eval with the plugin context in scope. ${where}. `
      + (site.parseError === undefined
        ? 'This tool classified the expression by parsing it and never evaluated it.'
        : `It does not parse: ${site.parseError}`),
    evidence: { file, path: site.path, snippet: snippet(site.expression) },
  })
}

/**
 * One `!!js` node in a field the loader keeps literal, where it silently
 * becomes a truthy object instead of a value.
 * @param file - package-relative YAML path.
 * @param site - the expression site.
 * @returns the finding.
 */
function inertExpression(file: string, site: ExpressionSite): Finding {
  return tierA({
    checkId: 'A7',
    name: 'js-expression-inert',
    subject: 'inert-slot',
    severity: 'medium',
    title: '`!!js` in a field the loader never interpolates',
    detail: 'The loader interpolates only a row\'s `config` (recursively) and the top-level node of its `disabled`. '
      + 'Everywhere else the expression stays literal, so this becomes a truthy `{ __jsExpr }` object and silently '
      + 'changes composition. The author believes this is live code and it is not, which means this layer has very '
      + 'likely never been validated.',
    evidence: { file, path: site.path, snippet: snippet(site.expression) },
  })
}

/** A8, A17 — patch layers that do not load at all. */
function checkPatchFailures(input: CheckInput): Finding[] {
  return input.patchFailures.map(failure => failure.error.singleBangTag
    ? tierA({
      checkId: 'A8',
      name: 'single-bang-js-tag',
      subject: failure.file,
      severity: 'medium',
      title: 'Patch layer uses the `!js` tag, which no harness accepts',
      detail: 'The dialect registers exactly one custom tag, `tag:yaml.org,2002:js`, whose shorthand is `!!js`. '
        + '`!js` is an unknown local tag and is a hard YAML parse error, so this file has never been loaded '
        + 'successfully by any harness — the plugin was published without ever being booted.',
      evidence: { file: failure.file, snippet: snippet(failure.error.message) },
    })
    : tierA({
      checkId: 'A17',
      name: 'patch-parse-error',
      subject: failure.file,
      severity: 'medium',
      title: 'Patch layer does not parse',
      detail: 'The declared patch layer cannot be read as a Cordis entry list, so mounting this package fails the '
        + 'profile boot. Nothing else in this file could be analysed.',
      evidence: { file: failure.file, snippet: snippet(failure.error.message) },
    }))
}

/** A9 — inserting a row that names a module the manifest does not account for. */
function checkInsertedModules(input: CheckInput): Finding[] {
  const declared = declaredPackages(input.manifest)
  const coreModules = new Set([...CORE_ROWS.values()].map(row => row.module))
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const row of patch.inserts) {
      const name = row.name
      if (name === null || LOADER_BUILTINS.has(name)) continue
      if (declared.has(name)) continue
      // A subpath export of a declared package resolves through that package.
      if ([...declared].some(pkg => name.startsWith(`${pkg}/`))) continue
      const isCore = coreModules.has(name)
      findings.push(tierA({
        checkId: 'A9',
        name: 'insert-undeclared-module',
        subject: name,
        severity: isCore ? 'medium' : 'high',
        title: `Inserted row "${row.id ?? '(unnamed)'}" mounts ${name}, which this package does not declare`,
        detail: isCore
          ? 'This is a harness-owned module, so it resolves from the profile install anchor even though this '
            + 'package lists no dependency on it. The manifest therefore does not describe everything this layer mounts.'
          : 'The module is in neither `dependencies`, `peerDependencies`, nor `optionalDependencies`. Whatever it '
            + 'resolves to at mount time is decided by the profile directory, not by this package.',
        evidence: { file: patch.file, path: `${row.path}.name`, snippet: snippet(name) },
      }))
    }
  }
  return findings
}

/** A10 — MCP server rows, which spawn processes or import remote tool catalogues. */
function checkMcpRows(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const row of patch.inserts) {
      if (row.name !== MCP_CLIENT_PACKAGE) continue
      const config = typeof row.config === 'object' && row.config !== null
        ? row.config as Record<string, unknown>
        : {}
      const stdio = config.transport === 'stdio'
      const command = typeof config.command === 'string' ? config.command : null
      const shown = isJsExpr(config.command)
        ? `!!js ${config.command.__jsExpr}`
        : command ?? String(config.url ?? '(no command or url)')
      findings.push(tierA({
        checkId: 'A10',
        name: 'mcp-server-row',
        subject: shown,
        severity: stdio ? 'critical' : 'high',
        title: stdio
          ? `Patch layer starts a local MCP server by running \`${shown}\``
          : 'Patch layer connects to a remote MCP server',
        detail: stdio
          ? 'A stdio MCP row spawns that executable directly with the configured args, env, and cwd. It does not '
            + 'go through ctx.subprocess or ctx.sandbox, it raises no approval prompt, and it passes no tool gate. '
            + 'Every tool the server advertises is then registered as mcp__<server>__<tool> with model-visible '
            + 'descriptions this package does not control.'
          : 'The row imports a tool catalogue from a remote server. The tool names and their model-visible '
            + 'descriptions are decided by that server at connect time, not by anything in this package.',
        evidence: { file: patch.file, path: `${row.path}.config`, snippet: snippet(shown) },
      }))
    }
  }
  return findings
}

/** A15 — pointing skill discovery at this package's own shipped markdown. */
function checkSkillRootRedirect(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  const rows = input.patches.flatMap(patch => [
    ...patch.overrides.map(override => ({ file: patch.file, path: override.path, id: override.id, config: override.config })),
    ...patch.inserts.map(row => ({ file: patch.file, path: row.path, id: row.id, config: row.config })),
  ])
  for (const row of rows) {
    if (row.id !== SKILL_FILESYSTEM_ROW) continue
    if (typeof row.config !== 'object' || row.config === null) continue
    const config = row.config as Record<string, unknown>
    const keys = SKILL_ROOT_CONFIG_KEYS.filter(key => key in config)
    if (keys.length === 0) continue
    const bundled = keys.includes('bundledSkillDir')
    findings.push(tierA({
      checkId: 'A15',
      name: 'skill-root-redirected',
      subject: keys.join(','),
      severity: 'high',
      title: `Patch layer redirects skill discovery via ${keys.map(key => `\`${key}\``).join(', ')}`,
      detail: 'Skill files reach the model verbatim, unescaped and uncapped. This row changes which directories '
        + 'the filesystem skill provider scans, which is the declaration that turns shipped markdown into model '
        + 'instructions.'
        + (bundled
          ? ' `bundledSkillDir` additionally marks the root trustedHost, which reads through raw Node fs and '
            + 'bypasses the ctx.fs sandbox.'
          : ''),
      evidence: { file: row.file, path: `${row.path}.config`, snippet: snippet(boundedJson(config)) },
    }))
  }
  return findings
}

/** A1, A11, A13, A14, A16, A18 — checks that read `package.json` alone. */
function checkManifest(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  const { manifest, source } = input

  const lifecycle = INSTALL_LIFECYCLE_SCRIPTS.filter(name => name in manifest.scripts)
  for (const name of lifecycle) {
    /* v8 ignore next -- `name` came from filtering the same object's own keys. */
    const command = manifest.scripts[name] ?? ''
    const signals = matchingLifecycleSignals(command)
    findings.push(tierA({
      checkId: 'A1',
      name: 'install-lifecycle-script',
      subject: name,
      severity: signals.length === 0 ? 'medium' : 'high',
      title: `Declares a \`${name}\` script, which runs at install time once allowed`,
      detail: 'This command would run at the user\'s uid as part of `dsh plugin add`, before the user has read a '
        + 'line of the package. Two things stand between it and execution, and neither is this package\'s doing: '
        + '`dsh plugin add` forwards its arguments to pnpm verbatim and adds no --ignore-scripts, but pnpm ≥10 '
        + 'blocks dependency lifecycle scripts by default until the exact package is listed under `allowBuilds` in '
        + 'the profile\'s pnpm-workspace.yaml — and the harness prints that instruction itself when a build is '
        + 'blocked (apps/cli/src/plugin.ts). Approving the prompt runs this command.'
        + (signals.length === 0
          ? ''
          : ` The command ${signals.map(signal => signal.meaning).join(', and ')}. A build hook runs something `
            + 'this package shipped; this one does not. The whole of it is in `package.json`, with no module to '
            + 'read.'),
      evidence: { file: 'package.json', path: `scripts.${name}`, snippet: snippet(command) },
    }))
  }

  for (const command of manifest.binNames) {
    findings.push(tierA({
      checkId: 'A22',
      name: 'installs-command',
      subject: command,
      severity: 'low',
      title: `Installs the command \`${command}\` on the user's PATH`,
      detail: 'A `bin` entry is linked into the profile\'s `node_modules/.bin` at install time. It is not run by '
        + 'the harness, but it is now a name the user, a script, or an agent shell tool can invoke, and it is not '
        + 'covered by anything in the profile.',
      evidence: { file: 'package.json', path: 'bin', snippet: snippet(command) },
    }))
  }

  const profileBundles = manifest.dsh.profile?.bundles ?? []
  if (profileBundles.length > 0) {
    findings.push(tierA({
      checkId: 'A20',
      name: 'profile-mounts-bundles',
      subject: 'dsh.profile.bundles',
      severity: 'high',
      title: `Declares a profile that mounts ${profileBundles.length} bundle(s)`,
      detail: 'A `dsh.profile.bundles` list makes this package a profile rather than a layer: the launcher resolves '
        + 'each named package, reads its `dsh.bundle.patch`, and mounts that layer '
        + '(packages/boot/app-boot/src/profile.ts). Everything those packages declare composes into the profile, '
        + 'and none of it is in this package or in this analysis.',
      evidence: { file: 'package.json', path: 'dsh.profile.bundles', snippet: snippet(profileBundles.join(', ')) },
    }))
  }

  const specifiers: [string, string, string][] = [
    ...Object.entries(manifest.dependencies).map(([k, v]) => ['dependencies', k, v] as [string, string, string]),
    ...Object.entries(manifest.optionalDependencies).map(([k, v]) => ['optionalDependencies', k, v] as [string, string, string]),
  ]
  for (const [field, name, specifier] of specifiers) {
    if (!MUTABLE_SPECIFIER.test(specifier)) continue
    findings.push(tierA({
      checkId: 'A11',
      name: 'non-registry-dependency',
      subject: `${field}.${name}`,
      severity: 'high',
      title: `Depends on ${name} through a non-registry specifier`,
      detail: 'The code behind this specifier can change without the version of this package changing, so nothing '
        + 'about this analysis carries forward to a later install. A git specifier additionally runs the '
        + 'dependency\'s `prepare` script at install time.',
      evidence: { file: 'package.json', path: `${field}.${name}`, snippet: snippet(specifier) },
    }))
  }

  if (manifest.files === null) {
    findings.push(tierA({
      checkId: 'A13',
      name: 'no-files-allowlist',
      subject: 'files',
      severity: 'low',
      title: 'No `files` allowlist in package.json',
      detail: 'Without an allowlist the published tarball is whatever was in the working tree minus npm\'s default '
        + 'ignores, so what ships is not what the manifest describes.',
      evidence: { file: 'package.json' },
    }))
  }

  const patch = manifest.dsh.bundle?.patch
  if (patch !== undefined) {
    const normalized = normalizePackagePath(patch)
    if (normalized === null) {
      findings.push(tierA({
        checkId: 'A14',
        name: 'bundle-patch-escapes-package',
        subject: 'dsh.bundle.patch',
        severity: 'critical',
        title: 'The declared `dsh.bundle.patch` path climbs out of the package directory',
        detail: 'The launcher resolves the patch as join(packageDir, declared) with no sanitisation, and `..` '
          + 'segments survive that join, so this package\'s mounted patch layer is read from a file it does not '
          + 'ship and this analysis cannot see. This tool did not follow the path.',
        evidence: { file: 'package.json', path: 'dsh.bundle.patch', snippet: snippet(patch) },
      }))
    } else if (!source.files.has(normalized)) {
      findings.push(tierA({
        checkId: 'A16',
        name: 'bundle-patch-missing',
        subject: 'dsh.bundle.patch',
        severity: 'medium',
        title: 'The declared `dsh.bundle.patch` file is not in the package',
        detail: 'The package declares a mounted patch layer whose file is absent — commonly a `files` allowlist '
          + 'that forgets it. Mounting this bundle fails the profile boot. An absolute path lands here too: '
          + '`join(packageDir, "/etc/passwd")` is `<packageDir>/etc/passwd`, which is inside the package and '
          + `simply does not exist. The path was resolved to \`${normalized}\` and nothing was read from it.`,
        evidence: { file: 'package.json', path: 'dsh.bundle.patch', snippet: snippet(patch) },
      }))
    }
  }

  for (const defect of manifest.defects) {
    findings.push(tierA({
      checkId: 'A18',
      name: 'manifest-defect',
      subject: defect,
      severity: 'low',
      title: `Malformed package.json field: ${defect}`,
      detail: 'The field was ignored. A manifest that npm and the harness read differently is worth knowing about.',
      evidence: { file: 'package.json', snippet: snippet(defect) },
    }))
  }
  return findings
}

/**
 * Whether the package ships anything a native build would compile.
 *
 * Skipped files count: a `.cc` the reader passed over for its size is still a
 * source in the tarball, and claiming a package has none because the analyzer
 * declined to read one would be wrong in the direction that raises a finding.
 * @param input - the decoded package.
 * @returns true when C-family source is present.
 */
function shipsNativeSource(input: CheckInput): boolean {
  const paths = [...input.source.files.keys(), ...input.source.skipped.map(entry => entry.path)]
  return paths.some(isNativeSource)
}

/**
 * A24 — a native build declaration, which is an install-time execution point
 * that appears in no entry the manifest declares.
 *
 * Tier A because the decidable half is the whole finding: the file is at the
 * package root or it is not, and npm's default install command for a package
 * that ships one and declares no `install` or `preinstall` script is
 * `node-gyp rebuild`. Nothing has to be inferred about the code to know that a
 * build runs, which is the same standard A1 and A22 are read at — a field npm
 * itself must read literally in order to act on it.
 *
 * **The file is not parsed and never evaluated.** GYP is Python-ish, not JSON:
 * single-quoted strings, `#` comments, trailing commas, and `conditions` whose
 * first element is a Python expression written as a string. There is no
 * maintained JavaScript parser for it — `node-gyp` shells out to Python — so
 * parsing it here would mean hand-rolling one for an attacker-controlled file,
 * and evaluating a condition is the one thing this tool may never do. It also
 * would not change the verdict: what distinguishes a build declaration from a
 * build step is the presence of an `actions`, `rules` or `postbuilds` key and
 * the shape of the command line under it, and both are literal text in the file
 * either way. The severity is therefore keyed on a key match plus the same
 * command signals A1 grades a lifecycle script by.
 * @param input - the decoded package.
 * @returns the finding, or none when the package ships no `binding.gyp`.
 */
function checkNativeBuild(input: CheckInput): Finding[] {
  const text = input.source.files.get(NATIVE_BUILD_FILE)
  if (text === undefined) return []
  const runsCommands = GYP_COMMAND_KEYS.test(text)
  const signals = runsCommands ? matchingLifecycleSignals(text) : []
  const empty = shipsNativeSource(input) ? '' : ' The package ships no C or C++ source, so there is nothing here for '
    + 'a compiler to build and the build step is the only effect the file has.'
  const first = signals[0]
  let at = 0
  if (first !== undefined) {
    /* v8 ignore next -- `first` is in the list because it matched this same text, so `exec` finds it again. */
    at = first.pattern.exec(text)?.index ?? 0
  }
  return [tierA({
    checkId: 'A24',
    name: 'native-build-declaration',
    subject: NATIVE_BUILD_FILE,
    severity: signals.length === 0 ? 'medium' : 'high',
    title: signals.length === 0
      ? 'Ships `binding.gyp`, which npm turns into an install-time build'
      : 'Ships a `binding.gyp` whose build steps run commands rather than a compiler',
    detail: 'A package that ships this file and declares no `install` or `preinstall` script gets `node-gyp rebuild` '
      + 'as its install command by default, and `node-gyp` evaluates the file to decide what that build does. The '
      + 'declaration is in none of the entry points a reader checks: not `main`, not `bin`, not `exports`, and not '
      + '`scripts`. It runs under the same gate as A1 — pnpm and npm block a dependency\'s build until the package is '
      + 'named in `allowBuilds` — but reaching that gate takes no key in `package.json` at all, which is why an '
      + 'ecosystem where install hooks are off by default is one where this path is worth reading.'
      + (signals.length === 0
        ? ' This file declares no `actions`, `rules` or `postbuilds` step whose command line does anything a compile '
          + 'does not, so what it describes is a build.'
        : ` It declares a build step whose command ${signals.map(signal => signal.meaning).join(', and ')}.`)
      + empty
      + ' The file was read as text, never parsed and never evaluated — GYP is Python-ish syntax whose conditions are '
      + 'Python expressions. Reading it that way is enough to decide that a build runs, which is this finding. It is '
      + 'not enough to decide what the build does, so the grade above reads the command line the way A1 reads a '
      + 'lifecycle script\'s.',
    evidence: {
      file: NATIVE_BUILD_FILE,
      path: lineColumn(text, at),
      snippet: snippet(text.slice(at, at + 400)),
    },
  })]
}

/** A12 — shipped markdown that reaches the model when it is discovered. */
function checkModelVisibleText(input: CheckInput): Finding[] {
  if (input.modelVisibleFiles.length === 0) return []
  return [tierA({
    checkId: 'A12',
    name: 'model-visible-text-shipped',
    subject: 'shipped-instructions',
    severity: 'low',
    title: `Ships ${input.modelVisibleFiles.length} model-visible instruction file(s)`,
    detail: 'Skill and agent-instruction markdown reaches the model verbatim, unescaped and uncapped. Shipping it '
      + 'in an npm package does not by itself put it in front of the model: it is discovered only when the plugin '
      + 'registers it through ctx.skills, when a patch row redirects a skill root into this package (A15), or when '
      + 'something copies it into the user\'s workspace. The text itself is scored separately by A21.',
    /* v8 ignore next -- the caller returns early on an empty list. */
    evidence: { file: input.modelVisibleFiles[0] ?? '', snippet: snippet(input.modelVisibleFiles.join(', ')) },
  })]
}

/** A23 — an inserted row substituting a service for its whole subtree. */
function checkServiceRemapping(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const row of patch.inserts) {
      for (const [field, names] of [['isolate', row.isolate], ['intercept', row.intercept]] as const) {
        const seams = names.filter(name => SEAM_KEYS.has(name))
        if (seams.length === 0) continue
        const critical = seams.some(name => SECURITY_SEAM_KEYS.has(name))
        findings.push(tierA({
          checkId: 'A23',
          name: 'row-service-remapping',
          subject: `${field}:${seams.join(',')}`,
          severity: critical ? 'critical' : 'high',
          title: `Inserted row "${row.id ?? '(unnamed)'}" re-maps ${seams.map(name => `\`${name}\``).join(', ')} via \`${field}\``,
          detail: field === 'isolate'
            ? 'The loader\'s isolate hook binds the named service to a fresh symbol realm for this row and every '
              + 'row beneath it (vendor/loader/src/config/isolate.ts), so a descendant that injects that name '
              + 'receives whatever this subtree provides instead of the profile\'s implementation. That is the same '
              + 'substitution as replacing the service in code, declared in YAML, with no code to read.'
            : 'The loader\'s intercept hook layers this row\'s own values over the named service for its whole '
              + 'subtree, so every descendant sees this package\'s version of it.'
            + (critical ? ' The named service is one whose purpose is to constrain what the agent may do.' : ''),
          evidence: { file: patch.file, path: `${row.path}.${field}`, snippet: snippet(names.join(', ')) },
        }))
      }
    }
  }
  return findings
}

/**
 * A21 — injection phrasing in shipped instruction markdown.
 *
 * This is Tier A rather than Tier B because there is no syntax between the
 * bytes and the model: a `SKILL.md` reaches the model verbatim, so the shipped
 * file *is* the prompt. There is nothing to obfuscate and therefore nothing for
 * a Tier C degradation to make unreliable — which is why it is exempt from the
 * downgrade that applies to every capability check. What is heuristic here is
 * the reading of the sentence, not the reading of the file, and the finding
 * says so.
 */
function checkInjectionText(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const path of input.modelVisibleFiles) {
    const text = input.source.files.get(path)
    /* v8 ignore next -- `modelVisibleFiles` is filtered from `source.files`'s own keys, so the lookup always hits. */
    if (text === undefined) continue
    for (const match of scanInjection(text)) {
      const evidence = { file: path, path: lineColumn(text, match.index), snippet: snippet(match.excerpt) }
      findings.push({
        checkId: 'A21',
        name: 'model-visible-injection',
        subject: match.ruleId,
        tier: 'A',
        severity: 'high',
        confidence: 'certain',
        title: `Shipped instruction file ${match.meaning}`,
        detail: `Heuristic \`${match.ruleId}\` matched shipped markdown. The file reaches the model verbatim, `
          + 'unescaped and uncapped, when it is discovered — there is no encoding step between these bytes and the '
          + 'model, which is why this is a verdict about the text rather than a capability report. Whether the '
          + 'sentence is an instruction or a discussion of one is a judgement this tool cannot make: the pattern '
          + 'will miss a rephrasing, and it can fire on a document that legitimately quotes an attack.',
        evidence,
        examples: [evidence],
        occurrences: 1,
        bypass: null,
      })
    }
  }
  return findings
}

/**
 * Run every Tier A check.
 *
 * The filter is the guard: a package that declares no `dsh.bundle.patch`
 * composes into no profile, so no reading of a Cordis row in it can be a
 * verdict about anything. `patches` is already empty in that case; this makes
 * the property structural rather than a consequence of how the input was built.
 * @param input - the decoded package.
 * @returns findings, unordered.
 */
export function runTierA(input: CheckInput): Finding[] {
  const findings = [
    ...checkManifest(input),
    ...checkNativeBuild(input),
    ...checkDisabledRows(input),
    ...checkOverriddenRows(input),
    ...checkExpressions(input),
    ...checkPatchFailures(input),
    ...checkInsertedModules(input),
    ...checkMcpRows(input),
    ...checkSkillRootRedirect(input),
    ...checkServiceRemapping(input),
    ...checkModelVisibleText(input),
    ...checkInjectionText(input),
  ]
  if (input.mountsAsBundle) return findings
  return findings.filter(finding => !PATCH_ROW_CHECKS.has(finding.checkId))
}
