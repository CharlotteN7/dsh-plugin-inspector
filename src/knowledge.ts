/**
 * Ground truth read out of the DeepSeek Harness checkout: the core row
 * inventory, the capability seam keys, the waterfall event set, and the
 * capabilities the harness's own sandbox denies untrusted code.
 *
 * Every table here cites the harness file it was transcribed from. These are
 * facts about a specific harness version, not opinions — when the harness
 * changes, these tables are what needs updating, and keeping them in one
 * module is what makes that a single reviewable diff.
 * @module dsh-plugin-inspector/knowledge
 */

/**
 * Harness version these tables were transcribed from — the version string in
 * the checkout's own `packages/bundle/*&#47;package.json`.
 */
export const HARNESS_REFERENCE = '0.1.0-rc.5'

/** The shipped bundles, each of which is one patch layer over the profile root. */
export type BundleName = 'base' | 'headless' | 'web-app'

/**
 * The three profile bundles the harness ships, mapped to what each one is.
 * A package that *is* one of these composes the core rows rather than modifying
 * somebody else's: `@deepseek-ai/dsh-web-app` disabling two dozen rows the base
 * layer inserted is the definition of a bundle, not an attack on one.
 * Transcribed from `packages/bundle/{base,headless,web-app}/package.json`.
 */
export const HARNESS_BUNDLE_PACKAGES: ReadonlyMap<string, BundleName> = new Map([
  ['@deepseek-ai/dsh-base', 'base'],
  ['@deepseek-ai/dsh-headless', 'headless'],
  ['@deepseek-ai/dsh-web-app', 'web-app'],
])

/** One row a shipped bundle defines. */
export interface CoreRow {
  /** The module specifier that implements the row. */
  readonly module: string
  /** Which shipped bundles insert this row. A profile may mount only some of them. */
  readonly bundles: readonly BundleName[]
}

/**
 * Every row the shipped bundles define, mapped from row id to the module that
 * implements it and the bundles that insert it. Transcribed from
 * `packages/bundle/{base,headless,web-app}/cordis.patch.yml`.
 *
 * A patch row whose `id` is a key here is modifying core behavior rather than
 * contributing its own. The name half matters because `applyEntryPatches`
 * treats `name` on a non-insert patch as an assertion guard: on mismatch it
 * warns and skips the whole patch, so a patch naming the wrong module silently
 * does nothing at all. The bundle half matters because the three layers are not
 * one profile: a `ui-*` row exists only where the web bundle is mounted, so a
 * headless profile never had it to lose.
 */
export const CORE_ROWS: ReadonlyMap<string, CoreRow> = new Map([
  ['agent', { module: '@deepseek-ai/dsh-agent', bundles: ['base'] }],
  ['agent-default-model', { module: '@deepseek-ai/dsh-agent-default-model', bundles: ['base'] }],
  ['agent-instructions', { module: '@deepseek-ai/dsh-agent-instructions', bundles: ['base'] }],
  ['agent-loop', { module: '@deepseek-ai/dsh-agent-loop', bundles: ['base'] }],
  ['agent-presets', { module: '@deepseek-ai/dsh-agent-presets', bundles: ['web-app'] }],
  ['api-gateway', { module: '@deepseek-ai/dsh-host-apiproxy', bundles: ['web-app'] }],
  ['api-remotes', { module: '@deepseek-ai/dsh-api-remotes', bundles: ['web-app'] }],
  ['approval', { module: '@deepseek-ai/dsh-user-approval', bundles: ['base'] }],
  ['attachment-local', { module: '@deepseek-ai/dsh-attachment-local', bundles: ['base'] }],
  ['bash-sandbox', { module: '@deepseek-ai/dsh-bash-sandbox', bundles: ['base'] }],
  ['client-hmr', { module: '@deepseek-ai/dsh-client-hmr', bundles: ['web-app'] }],
  ['client-runtime', { module: '@deepseek-ai/dsh-client-runtime', bundles: ['web-app'] }],
  ['code-runtime', { module: '@deepseek-ai/dsh-code-runtime-worker-thread', bundles: ['headless', 'web-app'] }],
  ['command-compact', { module: '@deepseek-ai/dsh-command-compact', bundles: ['base'] }],
  ['command-feedback', { module: '@deepseek-ai/dsh-command-feedback', bundles: ['base'] }],
  ['command-goal', { module: '@deepseek-ai/dsh-command-goal', bundles: ['base'] }],
  ['commands', { module: '@deepseek-ai/dsh-commands', bundles: ['base'] }],
  ['compaction-basic', { module: '@deepseek-ai/dsh-compaction-basic', bundles: ['base'] }],
  ['connection', { module: '@deepseek-ai/dsh-client-connection', bundles: ['web-app'] }],
  ['cordis-client-runner', { module: '@deepseek-ai/dsh-cordis-client-runner', bundles: ['web-app'] }],
  ['cordis-host-runner', { module: '@deepseek-ai/dsh-cordis-host-runner', bundles: ['web-app'] }],
  ['credentials', { module: '@deepseek-ai/dsh-credentials-local', bundles: ['base'] }],
  ['directory-picker', { module: '@deepseek-ai/dsh-host-directory-picker-auto', bundles: ['web-app'] }],
  ['fs-observation-policy', { module: '@deepseek-ai/dsh-fs-observation-policy', bundles: ['base'] }],
  ['fs-sandbox', { module: '@deepseek-ai/dsh-fs-sandbox', bundles: ['base'] }],
  ['goal', { module: '@deepseek-ai/dsh-goal', bundles: ['base'] }],
  ['goal-round-driver', { module: '@deepseek-ai/dsh-goal-round-driver', bundles: ['base'] }],
  ['headless-runner', { module: '@deepseek-ai/dsh-headless', bundles: ['headless'] }],
  ['headless-startup', { module: '@deepseek-ai/dsh-headless/startup', bundles: ['headless'] }],
  ['hmr', { module: '@deepseek-ai/cordis-plugin-hmr', bundles: ['base'] }],
  ['jobs', { module: '@deepseek-ai/dsh-jobs-local', bundles: ['base'] }],
  ['llm', { module: '@deepseek-ai/dsh-llm', bundles: ['base'] }],
  ['llm-deepseek', { module: '@deepseek-ai/dsh-llm-deepseek', bundles: ['base'] }],
  ['llm-pi-ai', { module: '@deepseek-ai/dsh-llm-pi-ai', bundles: ['base'] }],
  ['llm-retry', { module: '@deepseek-ai/dsh-llm-retry', bundles: ['base'] }],
  ['locale', { module: '@deepseek-ai/dsh-client-locale', bundles: ['web-app'] }],
  ['message-feedback', { module: '@deepseek-ai/dsh-message-feedback', bundles: ['web-app'] }],
  ['modules', { module: '@deepseek-ai/dsh-client-modules', bundles: ['web-app'] }],
  ['permission', { module: '@deepseek-ai/dsh-permission-presets', bundles: ['base'] }],
  ['plan-mode', { module: '@deepseek-ai/dsh-plan-mode', bundles: ['base'] }],
  ['plugin-inventory', { module: '@deepseek-ai/dsh-host-plugin-inventory', bundles: ['web-app'] }],
  ['pwsh-sandbox', { module: '@deepseek-ai/dsh-pwsh-sandbox', bundles: ['base'] }],
  ['repeat-tool-reminder', { module: '@deepseek-ai/dsh-repeat-tool-reminder', bundles: ['base'] }],
  ['sandbox', { module: '@deepseek-ai/dsh-sandbox-local', bundles: ['base'] }],
  ['sandbox-policy', { module: '@deepseek-ai/dsh-sandbox-policy', bundles: ['base'] }],
  ['session', { module: '@deepseek-ai/dsh-session', bundles: ['base'] }],
  ['session-checkpoint-policy', { module: '@deepseek-ai/dsh-session-checkpoint-policy', bundles: ['base'] }],
  ['session-log-download', { module: '@deepseek-ai/dsh-session-log-export', bundles: ['web-app'] }],
  ['session-persistence-jsonl', { module: '@deepseek-ai/dsh-session-persistence-jsonl', bundles: ['base'] }],
  ['session-projection', { module: '@deepseek-ai/dsh-session-projection', bundles: ['base'] }],
  ['session-projection-cache', { module: '@deepseek-ai/dsh-session-projection-cache', bundles: ['web-app'] }],
  ['session-query-sqlite', { module: '@deepseek-ai/dsh-session-query-sqlite', bundles: ['base'] }],
  ['session-stats', { module: '@deepseek-ai/dsh-session-stats', bundles: ['web-app'] }],
  ['session-telemetry-otel', { module: '@deepseek-ai/dsh-session-telemetry-otel', bundles: ['base'] }],
  ['session-title', { module: '@deepseek-ai/dsh-session-title', bundles: ['base'] }],
  ['session-title-llm', { module: '@deepseek-ai/dsh-session-title-first-prompt-llm', bundles: ['base'] }],
  ['settings', { module: '@deepseek-ai/dsh-settings-file', bundles: ['base'] }],
  ['shell-env', { module: '@deepseek-ai/dsh-shell-env', bundles: ['base'] }],
  ['skill', { module: '@deepseek-ai/dsh-skill', bundles: ['base'] }],
  ['skill-badge', { module: '@deepseek-ai/dsh-skill-badge', bundles: ['base'] }],
  ['skill-filesystem', { module: '@deepseek-ai/dsh-skill-filesystem', bundles: ['base'] }],
  ['spill-local', { module: '@deepseek-ai/dsh-spill-local', bundles: ['base'] }],
  ['spill-policy', { module: '@deepseek-ai/dsh-spill-policy', bundles: ['base'] }],
  ['storage', { module: '@deepseek-ai/dsh-storage', bundles: ['web-app'] }],
  ['storage-domain', { module: '@deepseek-ai/dsh-storage-domain', bundles: ['web-app'] }],
  ['storage-json', { module: '@deepseek-ai/dsh-storage-json', bundles: ['web-app'] }],
  ['subagent', { module: '@deepseek-ai/dsh-subagent', bundles: ['base'] }],
  ['subagent-fork-in-process', { module: '@deepseek-ai/dsh-subagent-fork-in-process', bundles: ['base'] }],
  ['subagent-spawn-in-process', { module: '@deepseek-ai/dsh-subagent-spawn-in-process', bundles: ['base'] }],
  ['subprocess', { module: '@deepseek-ai/dsh-subprocess-local', bundles: ['base'] }],
  ['system-prompt', { module: '@deepseek-ai/dsh-system-prompt', bundles: ['base'] }],
  ['timeout-policy', { module: '@deepseek-ai/dsh-tool-call-timeout-policy', bundles: ['base'] }],
  ['timer', { module: '@deepseek-ai/cordis-plugin-timer', bundles: ['base'] }],
  ['token-meter', { module: '@deepseek-ai/dsh-token-meter', bundles: ['base'] }],
  ['tool-bash', { module: '@deepseek-ai/dsh-tool-bash', bundles: ['base'] }],
  ['tool-fs', { module: '@deepseek-ai/dsh-tool-fs', bundles: ['base'] }],
  ['tool-fs-search', { module: '@deepseek-ai/dsh-tool-fs-search', bundles: ['base'] }],
  ['tool-goal', { module: '@deepseek-ai/dsh-tool-goal', bundles: ['base'] }],
  ['tool-jobs', { module: '@deepseek-ai/dsh-tool-jobs', bundles: ['base'] }],
  ['tool-pwsh', { module: '@deepseek-ai/dsh-tool-pwsh', bundles: ['base'] }],
  ['tool-ralph', { module: '@deepseek-ai/dsh-tool-ralph', bundles: ['base'] }],
  ['tool-result-pruner', { module: '@deepseek-ai/dsh-compaction-tool-result-pruner', bundles: ['base'] }],
  ['tool-skill', { module: '@deepseek-ai/dsh-tool-skill', bundles: ['base'] }],
  ['tool-str-replace-editor', { module: '@deepseek-ai/dsh-tool-str-replace-editor', bundles: ['base'] }],
  ['tool-subagent', { module: '@deepseek-ai/dsh-tool-subagent', bundles: ['base'] }],
  ['tool-subagent-control', { module: '@deepseek-ai/dsh-tool-subagent-control', bundles: ['base'] }],
  ['tool-subagent-fork', { module: '@deepseek-ai/dsh-tool-subagent', bundles: ['base'] }],
  ['tool-subagent-list-agents', { module: '@deepseek-ai/dsh-tool-subagent-control/list-agents', bundles: ['base'] }],
  ['tool-subagent-report', { module: '@deepseek-ai/dsh-tool-subagent-report', bundles: ['base'] }],
  ['tool-todo', { module: '@deepseek-ai/dsh-tool-todo', bundles: ['base'] }],
  ['tool-web', { module: '@deepseek-ai/dsh-tool-web', bundles: ['base'] }],
  ['tool-workflow', { module: '@deepseek-ai/dsh-tool-workflow', bundles: ['base'] }],
  ['tools', { module: '@deepseek-ai/dsh-tools', bundles: ['base'] }],
  ['typert', { module: '@deepseek-ai/dsh-typert-registry', bundles: ['base'] }],
  ['typert-gateway', { module: '@deepseek-ai/dsh-api-gateway', bundles: ['base'] }],
  ['typert-loader', { module: '@deepseek-ai/dsh-typert-loader', bundles: ['base'] }],
  ['ui-agent-preset', { module: '@deepseek-ai/dsh-client-ui-agent-preset', bundles: ['web-app'] }],
  ['ui-commands', { module: '@deepseek-ai/dsh-client-ui-commands', bundles: ['web-app'] }],
  ['ui-conversation', { module: '@deepseek-ai/dsh-client-ui-conversation', bundles: ['web-app'] }],
  ['ui-cordis', { module: '@deepseek-ai/dsh-client-ui-cordis', bundles: ['web-app'] }],
  ['ui-deliverables', { module: '@deepseek-ai/dsh-client-ui-deliverables', bundles: ['web-app'] }],
  ['ui-goal', { module: '@deepseek-ai/dsh-client-ui-goal', bundles: ['web-app'] }],
  ['ui-input-trigger', { module: '@deepseek-ai/dsh-client-ui-input-trigger', bundles: ['web-app'] }],
  ['ui-jobs', { module: '@deepseek-ai/dsh-client-ui-jobs', bundles: ['web-app'] }],
  ['ui-layout', { module: '@deepseek-ai/dsh-client-ui-layout', bundles: ['web-app'] }],
  ['ui-message-feedback', { module: '@deepseek-ai/dsh-client-ui-message-feedback', bundles: ['web-app'] }],
  ['ui-model-selection', { module: '@deepseek-ai/dsh-client-ui-model-selection', bundles: ['web-app'] }],
  ['ui-permission', { module: '@deepseek-ai/dsh-client-ui-permission-presets', bundles: ['web-app'] }],
  ['ui-plan', { module: '@deepseek-ai/dsh-client-ui-plan', bundles: ['web-app'] }],
  ['ui-settings', { module: '@deepseek-ai/dsh-client-ui-settings', bundles: ['web-app'] }],
  ['ui-settings-general', { module: '@deepseek-ai/dsh-client-ui-settings-general', bundles: ['web-app'] }],
  ['ui-settings-models', { module: '@deepseek-ai/dsh-client-ui-settings-models', bundles: ['web-app'] }],
  ['ui-settings-plugin-inventory', { module: '@deepseek-ai/dsh-client-ui-settings-plugin-inventory', bundles: ['web-app'] }],
  ['ui-settings-plugins', { module: '@deepseek-ai/dsh-client-ui-settings-plugins', bundles: ['web-app'] }],
  ['ui-sidebar', { module: '@deepseek-ai/dsh-client-ui-sidebar', bundles: ['web-app'] }],
  ['ui-skill', { module: '@deepseek-ai/dsh-client-ui-skill', bundles: ['web-app'] }],
  ['ui-subagent', { module: '@deepseek-ai/dsh-client-ui-subagent', bundles: ['web-app'] }],
  ['ui-theme', { module: '@deepseek-ai/dsh-client-ui-theme', bundles: ['web-app'] }],
  ['ui-tool', { module: '@deepseek-ai/dsh-client-ui-tool', bundles: ['web-app'] }],
  ['ui-trajectory', { module: '@deepseek-ai/dsh-client-ui-trajectory', bundles: ['web-app'] }],
  ['ui-user-questions', { module: '@deepseek-ai/dsh-client-ui-user-questions', bundles: ['web-app'] }],
  ['ui-workflow-run', { module: '@deepseek-ai/dsh-client-ui-workflow-run', bundles: ['web-app'] }],
  ['ui-workspace', { module: '@deepseek-ai/dsh-client-ui-workspace', bundles: ['web-app'] }],
  ['user-questions', { module: '@deepseek-ai/dsh-user-questions', bundles: ['base'] }],
  ['web', { module: '@deepseek-ai/dsh-web', bundles: ['base'] }],
  ['web-runtime', { module: '@deepseek-ai/dsh-web-app', bundles: ['web-app'] }],
  ['web-search-deepseek', { module: '@deepseek-ai/dsh-web-search-deepseek', bundles: ['base'] }],
  ['web-startup', { module: '@deepseek-ai/dsh-web-app/startup', bundles: ['web-app'] }],
  ['webserver', { module: '@deepseek-ai/dsh-host-webserver', bundles: ['web-app'] }],
  ['workflow-worker-thread', { module: '@deepseek-ai/dsh-workflow-worker-thread', bundles: ['base'] }],
  ['workspace', { module: '@deepseek-ai/dsh-workspace', bundles: ['web-app'] }],
])

/** Row ids the shipped bundles define. */
export const CORE_ROW_IDS: ReadonlySet<string> = new Set(CORE_ROWS.keys())

/**
 * The core rows whose whole purpose is to constrain what the agent may do.
 * Disabling or reconfiguring one of these from a third-party patch layer is
 * the highest-value finding this tool produces, and it is plain YAML.
 *
 * Each entry names what stops holding when the row stops running.
 */
export const SECURITY_ROW_IDS: ReadonlyMap<string, string> = new Map([
  ['approval', 'user approval prompts for tool calls'],
  ['permission', 'the permission preset that decides which tools may run unattended'],
  ['sandbox', 'the sandbox service'],
  ['sandbox-policy', 'the policy that decides what the sandbox permits'],
  ['bash-sandbox', 'sandboxing of bash tool invocations'],
  ['pwsh-sandbox', 'sandboxing of PowerShell tool invocations'],
  ['fs-sandbox', 'filesystem access confinement'],
  ['fs-observation-policy', 'the read-before-write policy on file edits'],
  ['subprocess', 'the mediated subprocess service tools are supposed to go through'],
  ['credentials', 'credential storage'],
  ['timeout-policy', 'tool execution timeouts'],
  ['spill-policy', 'the policy bounding oversized tool output'],
  ['session-persistence-jsonl', 'the session log, which is the audit record'],
  ['session-telemetry-otel', 'telemetry export'],
  ['session-checkpoint-policy', 'session checkpointing'],
  ['tools', 'the tool registry itself'],
  ['agent-loop', 'the agent loop itself'],
])

/**
 * Capability seam keys from
 * `packages/extensions/tool-cordis/src/api-catalog.ts` (`SERVICE_API[].key`).
 * A plugin calling `ctx.provide(key, …)` or `ctx.set(key, …)` on one of these
 * replaces a core service for every consumer in its scope.
 */
export const SEAM_KEYS: ReadonlySet<string> = new Set([
  'agentDefaultModel', 'agentLoop', 'agentPresets', 'agents', 'apiProxy', 'approval',
  'attachments', 'clientModules', 'codeRuntime', 'commands', 'compaction', 'credentials',
  'directoryPicker', 'e2b', 'fs', 'goals', 'invariants', 'jobs', 'llm', 'lsp',
  'messageFeedback', 'permissionPresets', 'planMode', 'sandbox', 'sandboxPolicy',
  'sessionPersistence', 'sessionProjectionCache', 'sessionProjections', 'sessionQuery',
  'sessionReferenceResolver', 'sessions', 'sessionTelemetry', 'sessionTitle', 'settings',
  'shell', 'shellEnv', 'skills', 'spillStore', 'storage', 'storageDomain', 'subagents',
  'subprocess', 'systemPrompt', 'terminals', 'timer', 'tokenMeter', 'toolResultPruner',
  'tools', 'typert', 'typertGateway', 'userQuestions', 'web', 'webServer', 'workflowEngine',
  'workspaceRegistry',
])

/** The subset of {@link SEAM_KEYS} whose replacement removes a constraint. */
export const SECURITY_SEAM_KEYS: ReadonlySet<string> = new Set([
  'approval', 'sandbox', 'sandboxPolicy', 'permissionPresets', 'credentials', 'subprocess',
  'shell', 'fs', 'tools', 'agentLoop', 'sessionPersistence', 'sessionTelemetry', 'invariants',
])

/**
 * Waterfall events, from `EVENT_API` in the api-catalog. A listener on one of
 * these receives a trailing `next` and MUST call it to delegate; returning
 * without calling it short-circuits the chain including the built-in behavior.
 *
 * Note there is no `fs/read-intent` — the intent family is write and edit only.
 */
export const WATERFALL_EVENTS: ReadonlySet<string> = new Set([
  'agent/pre-step', 'agent/request', 'agent/request-error', 'approval/request',
  'fs/edit-intent', 'fs/write-intent', 'llm/stream', 'session-telemetry/record',
  'system-prompt/assemble', 'tools/code-dispatch-log', 'tools/execute',
  'tools/post-execute', 'tools/pre-execute',
])

/** Waterfall events whose short-circuit removes a decision the user would otherwise make. */
export const DECISION_EVENTS: ReadonlySet<string> = new Set([
  'approval/request', 'tools/pre-execute', 'tools/execute', 'fs/write-intent', 'fs/edit-intent',
])

/**
 * Globals the dynamic-package sandbox (`cordis-host-runner/src/sandbox.ts`)
 * traps and redirects to a `ctx` service, plus `process`, which it leaves
 * `undefined`. An installed bundle layer is a plain ESM import and gets none of
 * these restrictions — which is exactly why using one is worth reporting.
 */
export const SANDBOX_DENIED_GLOBALS: ReadonlyMap<string, string> = new Map([
  ['require', "redirected to ctx services (inject: ['fs'] / ['web'] / ['bash'])"],
  ['fetch', "redirected to the cordis web service (inject: ['web'])"],
  ['setTimeout', "redirected to the cordis timer service (inject: ['timer'])"],
  ['setInterval', "redirected to the cordis timer service (inject: ['timer'])"],
  ['setImmediate', "redirected to the cordis timer service (inject: ['timer'])"],
])

/**
 * Node builtins that start or evaluate code off the mediated path. A mounted
 * layer importing one of these is doing what `ctx.subprocess` and `ctx.sandbox`
 * exist to mediate, from a position where nothing mediates it.
 */
export const UNMEDIATED_PROCESS_MODULES: ReadonlyMap<string, string> = new Map([
  ['child_process', 'spawns processes without ctx.subprocess or ctx.sandbox'],
  ['worker_threads', 'runs code in a thread the harness does not supervise'],
  ['vm', 'evaluates code outside every harness seam'],
])

/**
 * Modules and globals that move bytes off the machine. The harness's own
 * dynamic-package sandbox traps `fetch` and redirects it to the `ctx.web`
 * service; a mounted layer gets no such redirect.
 */
export const NETWORK_MODULES: ReadonlySet<string> = new Set([
  'http', 'https', 'http2', 'net', 'tls', 'dgram',
  'undici', 'axios', 'node-fetch', 'got', 'superagent', 'ws', 'request',
])

/**
 * Filesystem modules that bypass `ctx.fs`. Reads and writes through these are
 * invisible to `fs/write-intent`, `fs/edit-intent`, `fs/observed`, and the
 * `fs-sandbox` row, so no policy sees them.
 */
export const UNMEDIATED_FS_MODULES: ReadonlySet<string> = new Set(['fs', 'fs/promises'])

/** The npm package that turns a Cordis row into an MCP server connection. */
export const MCP_CLIENT_PACKAGE = '@deepseek-ai/dsh-mcp-client'

/** The row id that owns filesystem skill discovery, and whose config selects the roots. */
export const SKILL_FILESYSTEM_ROW = 'skill-filesystem'

/** `skill-filesystem` config keys that point discovery at a new directory. */
export const SKILL_ROOT_CONFIG_KEYS: readonly string[] = ['customSkillDirs', 'bundledSkillDir']

/**
 * `package.json` script names npm and pnpm run around installation. A plugin
 * only needs one of these to run code before the user has read a line of it.
 */
export const INSTALL_LIFECYCLE_SCRIPTS: readonly string[] = [
  'preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'preprepare', 'postprepare',
]

/** Entry fields the loader never interpolates: a `!!js` node here is inert data. */
export const STATIC_ENTRY_FIELDS: readonly string[] = [
  'id', 'name', 'group', 'inject', 'intercept', 'isolate',
]

/**
 * Calls a `!!js` expression may make that reach nothing the harness does not
 * already hand it.
 *
 * `dsh-app-boot` does `ctx.provide('dshHomePath', dshHomePath)` before mounting
 * any entry (`packages/boot/app-boot/src/index.ts`), and the loader evaluates
 * every expression under `with (ctx)`, so `dshHomePath(...)` is in scope by
 * design and documented as such in that package's README. The two `process`
 * reads are the ones the shipped bundles use.
 */
export const HARNESS_INERT_CALLS: ReadonlySet<string> = new Set([
  'dshHomePath', 'process.cwd', 'process.uptime',
])

/**
 * The entry fields that decide which services a row sees, and which of them it
 * substitutes for its subtree.
 *
 * `isolate` is the sharpest: `vendor/loader/src/config/isolate.ts` re-maps a
 * named service to a fresh symbol realm, so every descendant that injects that
 * name gets the row's realm instead of the profile's. Setting it on a security
 * service is a Tier A declaration with the same reach as replacing the service
 * in code, and it is plain YAML.
 */
export const SERVICE_REMAPPING_FIELDS: readonly string[] = ['isolate', 'intercept']
