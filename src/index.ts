/**
 * `dsh-plugin-inspector` — static pre-install analysis of a DeepSeek Harness
 * plugin.
 *
 * The library face of the tool, for callers that want the report rather than
 * the exit code. {@link inspect} decodes a plugin directory or npm tarball,
 * runs the three check tiers over the decoded form, and returns a
 * {@link Report}. It never installs, builds, imports, spawns, or evaluates
 * anything from the analysed package.
 *
 * The ceiling is triage, not containment. See `README.md` §Limitations.
 * @module dsh-plugin-inspector
 */

export { analyze, exceedsThreshold, inspect, TOOL_NAME, TOOL_VERSION } from './inspect.ts'
export { inspectFromNpm, precheck } from './npm.ts'
export {
  DEFAULT_REGISTRY,
  fetchVerifiedTarball,
  parseSpec,
  RegistryError,
  resolvePackage,
  verifyIntegrity,
  type PackageSpec,
  type RegistryOptions,
  type ResolvedPackage,
  type VerifiedTarball,
} from './registry.ts'
export { renderHuman, renderJson } from './report.ts'
export {
  classifyExpression,
  isJsExpr,
  parsePatchDocument,
  patchSchema,
  PatchParseError,
  type ExpressionClass,
  type ExpressionSite,
  type ExpressionSlot,
  type InsertedRow,
  type JsExprNode,
  type OverridePatch,
  type PatchDocument,
} from './cordis-yaml.ts'
export { declaredPackages, ManifestError, parseManifest, type PackageManifest } from './manifest.ts'
export {
  DEFAULT_LIMITS,
  loadSource,
  loadTarballBuffer,
  SourceError,
  type PluginSource,
  type ReadLimits,
  type SourceKind,
} from './source.ts'
export { globMatch, publishSet, type PublishBasis, type PublishInputs, type PublishSet } from './publish.ts'
export { INJECTION_RULES, scanInjection, type InjectionMatch, type InjectionRule } from './injection.ts'
export {
  compareFindings,
  SEVERITIES,
  SEVERITY_RANK,
  summarize,
  type AnalysisIntegrity,
  type Confidence,
  type Evidence,
  type Facts,
  type Finding,
  type RegistryProvenance,
  type Report,
  type Severity,
  type Tier,
} from './model.ts'
export {
  CORE_ROWS,
  CORE_ROW_IDS,
  HARNESS_BUNDLE_PACKAGES,
  HARNESS_REFERENCE,
  SEAM_KEYS,
  SECURITY_ROW_IDS,
  WATERFALL_EVENTS,
  type BundleName,
  type CoreRow,
} from './knowledge.ts'
