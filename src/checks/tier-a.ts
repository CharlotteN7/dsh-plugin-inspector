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
import { snippet } from '../files.ts'
import {
  CORE_ROWS,
  INSTALL_LIFECYCLE_SCRIPTS,
  MCP_CLIENT_PACKAGE,
  SECURITY_ROW_IDS,
  SKILL_FILESYSTEM_ROW,
  SKILL_ROOT_CONFIG_KEYS,
} from '../knowledge.ts'
import { declaredPackages } from '../manifest.ts'
import type { Finding, Severity } from '../model.ts'
import type { CheckInput } from './input.ts'

/** Loader builtins that are entry names but not resolvable npm packages. */
const LOADER_BUILTINS: ReadonlySet<string> = new Set([
  'cordis:include', 'cordis:group',
  '@deepseek-ai/cordis-plugin-group', '@deepseek-ai/cordis-plugin-include',
])

/** Specifier prefixes that do not pin an immutable registry artifact. */
const MUTABLE_SPECIFIER = /^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:)/

/** How much reach each `!!js` classification represents. */
const EXPRESSION_SEVERITY: Readonly<Record<ExpressionClass, Severity>> = {
  'module-access': 'critical',
  mutation: 'high',
  call: 'high',
  unparseable: 'medium',
  'inert-read': 'low',
  literal: 'low',
}

/** What each `!!js` classification means, in one clause. */
const EXPRESSION_MEANING: Readonly<Record<ExpressionClass, string>> = {
  'module-access': 'reaches the module system, the global object, or the evaluator',
  mutation: 'writes to something rather than only reading',
  call: 'calls a function',
  unparseable: 'does not parse, so the entry cannot mount',
  'inert-read': 'reads an identifier',
  literal: 'is a constant',
}

/**
 * Build one finding, keeping every Tier A finding at `certain` confidence and
 * `null` bypass — a structured declaration has no syntactic evasion.
 * @param finding - everything but the fixed fields.
 * @returns the complete finding.
 */
function tierA(finding: Omit<Finding, 'tier' | 'confidence' | 'bypass'>): Finding {
  return { ...finding, tier: 'A', confidence: 'certain', bypass: null }
}

/**
 * Normalise a manifest-declared relative path to the package-relative POSIX
 * form used as map keys, or report that it leaves the package.
 * @param declared - the path exactly as the manifest declares it.
 * @returns the normalised path, or `null` when it escapes the package root.
 */
function normalizePackagePath(declared: string): string | null {
  if (declared.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(declared)) return null
  const segments: string[] = []
  for (const segment of declared.split(/[\\/]/)) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      if (segments.length === 0) return null
      segments.pop()
      continue
    }
    segments.push(segment)
  }
  return segments.join('/')
}

/** A2, A3 — a patch layer switching a core row off. */
function checkDisabledRows(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const override of patch.overrides) {
      // YAML cannot produce `undefined`, so absent and unset are the same here.
      if (override.disabled === undefined || override.disabled === false) continue
      const stops = SECURITY_ROW_IDS.get(override.id)
      const expression = isJsExpr(override.disabled) ? override.disabled.__jsExpr : null
      const shown = expression === null ? JSON.stringify(override.disabled) : `!!js ${expression}`
      if (stops !== undefined) {
        findings.push(tierA({
          checkId: 'A2',
          name: 'security-row-disabled',
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
      if (!CORE_ROWS.has(override.id)) continue
      findings.push(tierA({
        checkId: 'A3',
        name: 'core-row-disabled',
        severity: 'high',
        title: `Patch layer disables the core row "${override.id}"`,
        detail: 'This layer applies after @deepseek-ai/dsh-base and removes a row the shipped profile mounts.',
        evidence: { file: patch.file, path: `${override.path}.disabled`, snippet: snippet(shown) },
      }))
    }
  }
  return findings
}

/** A4, A5 — a patch layer rewriting a core row it did not define. */
function checkOverriddenRows(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const override of patch.overrides) {
      const coreName = CORE_ROWS.get(override.id)
      if (coreName === undefined) continue
      if (override.nameGuard !== null && override.nameGuard !== coreName) {
        findings.push(tierA({
          checkId: 'A4',
          name: 'patch-name-guard-mismatch',
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
      const isSecurity = SECURITY_ROW_IDS.has(override.id)
      findings.push(tierA({
        checkId: 'A5',
        name: 'core-row-overridden',
        severity: isSecurity ? 'high' : 'medium',
        title: `Patch layer rewrites ${rewritten.map(key => `\`${key}\``).join(', ')} on the core row "${override.id}"`,
        detail: `The row is ${coreName}. Patch overrides are shallow whole-value replacements, not merges, so `
          + `overriding \`config\` discards that row's entire shipped configuration rather than adding to it.`
          + (isSecurity ? ` This row provides ${SECURITY_ROW_IDS.get(override.id) ?? 'a core constraint'}.` : ''),
        evidence: { file: patch.file, path: override.path, snippet: snippet(rewritten.join(', ')) },
      }))
    }
  }
  return findings
}

/** A6, A7 — the `!!js` inventory. */
function checkExpressions(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const patch of input.patches) {
    for (const site of patch.expressions) {
      findings.push(site.slot === 'inert' ? inertExpression(patch.file, site) : liveExpression(patch.file, site))
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
  const coreModules = new Set(CORE_ROWS.values())
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
      severity: 'high',
      title: `Patch layer redirects skill discovery via ${keys.map(key => `\`${key}\``).join(', ')}`,
      detail: 'Skill files reach the model verbatim, unescaped and uncapped. This row changes which directories '
        + 'the filesystem skill provider scans, which is the declaration that turns shipped markdown into model '
        + 'instructions.'
        + (bundled
          ? ' `bundledSkillDir` additionally marks the root trustedHost, which reads through raw Node fs and '
            + 'bypasses the ctx.fs sandbox.'
          : ''),
      evidence: { file: row.file, path: `${row.path}.config`, snippet: snippet(JSON.stringify(config)) },
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
    findings.push(tierA({
      checkId: 'A1',
      name: 'install-lifecycle-script',
      severity: 'high',
      title: `Runs a \`${name}\` script during installation`,
      detail: 'This command runs at the user\'s uid as part of `dsh plugin add`, before the user has read a line '
        + 'of the package. `dsh plugin add` forwards its arguments to pnpm verbatim and adds no --ignore-scripts.',
      evidence: { file: 'package.json', path: `scripts.${name}`, snippet: snippet(manifest.scripts[name] ?? '') },
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
        severity: 'critical',
        title: 'The declared `dsh.bundle.patch` path leaves the package directory',
        detail: 'The launcher resolves the patch as join(packageDir, declared) with no sanitisation, so this '
          + 'package\'s mounted patch layer is read from a file it does not ship and this analysis cannot see. '
          + 'This tool did not follow the path.',
        evidence: { file: 'package.json', path: 'dsh.bundle.patch', snippet: snippet(patch) },
      }))
    } else if (!source.files.has(normalized)) {
      findings.push(tierA({
        checkId: 'A16',
        name: 'bundle-patch-missing',
        severity: 'medium',
        title: 'The declared `dsh.bundle.patch` file is not in the package',
        detail: 'The package declares a mounted patch layer whose file is absent — commonly a `files` allowlist '
          + 'that forgets it. Mounting this bundle fails the profile boot.',
        evidence: { file: 'package.json', path: 'dsh.bundle.patch', snippet: snippet(patch) },
      }))
    }
  }

  for (const defect of manifest.defects) {
    findings.push(tierA({
      checkId: 'A18',
      name: 'manifest-defect',
      severity: 'low',
      title: `Malformed package.json field: ${defect}`,
      detail: 'The field was ignored. A manifest that npm and the harness read differently is worth knowing about.',
      evidence: { file: 'package.json', snippet: snippet(defect) },
    }))
  }
  return findings
}

/** A12 — shipped markdown that reaches the model when it is discovered. */
function checkModelVisibleText(input: CheckInput): Finding[] {
  if (input.modelVisibleFiles.length === 0) return []
  return [tierA({
    checkId: 'A12',
    name: 'model-visible-text-shipped',
    severity: 'low',
    title: `Ships ${input.modelVisibleFiles.length} model-visible instruction file(s)`,
    detail: 'Skill and agent-instruction markdown reaches the model verbatim, unescaped and uncapped. Shipping it '
      + 'in an npm package does not by itself put it in front of the model: it is discovered only when the plugin '
      + 'registers it through ctx.skills, when a patch row redirects a skill root into this package (A15), or when '
      + 'something copies it into the user\'s workspace. The text itself is scored separately by B10.',
    evidence: { file: input.modelVisibleFiles[0] ?? '', snippet: snippet(input.modelVisibleFiles.join(', ')) },
  })]
}

/**
 * Run every Tier A check.
 * @param input - the decoded package.
 * @returns findings, unordered.
 */
export function runTierA(input: CheckInput): Finding[] {
  return [
    ...checkManifest(input),
    ...checkDisabledRows(input),
    ...checkOverriddenRows(input),
    ...checkExpressions(input),
    ...checkPatchFailures(input),
    ...checkInsertedModules(input),
    ...checkMcpRows(input),
    ...checkSkillRootRedirect(input),
    ...checkModelVisibleText(input),
  ]
}
