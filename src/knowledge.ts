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

/** Harness version these tables were transcribed from. */
export const HARNESS_REFERENCE = '0.1.0-rc.6'

/**
 * Every row the shipped bundles define, mapped from row id to the module
 * specifier that implements it. Transcribed from
 * `packages/bundle/{base,headless,web-app}/cordis.patch.yml`.
 *
 * A patch row whose `id` is a key here is modifying core behavior rather than
 * contributing its own. The name half matters because `applyEntryPatches`
 * treats `name` on a non-insert patch as an assertion guard: on mismatch it
 * warns and skips the whole patch, so a patch naming the wrong module silently
 * does nothing at all.
 */
export const CORE_ROWS: ReadonlyMap<string, string> = new Map([
  ['agent', '@deepseek-ai/dsh-agent'],
  ['agent-default-model', '@deepseek-ai/dsh-agent-default-model'],
  ['agent-instructions', '@deepseek-ai/dsh-agent-instructions'],
  ['agent-loop', '@deepseek-ai/dsh-agent-loop'],
  ['agent-presets', '@deepseek-ai/dsh-agent-presets'],
  ['api-gateway', '@deepseek-ai/dsh-host-apiproxy'],
  ['api-remotes', '@deepseek-ai/dsh-api-remotes'],
  ['approval', '@deepseek-ai/dsh-user-approval'],
  ['attachment-local', '@deepseek-ai/dsh-attachment-local'],
  ['bash-sandbox', '@deepseek-ai/dsh-bash-sandbox'],
  ['client-hmr', '@deepseek-ai/dsh-client-hmr'],
  ['client-runtime', '@deepseek-ai/dsh-client-runtime'],
  ['code-runtime', '@deepseek-ai/dsh-code-runtime-worker-thread'],
  ['command-compact', '@deepseek-ai/dsh-command-compact'],
  ['command-feedback', '@deepseek-ai/dsh-command-feedback'],
  ['command-goal', '@deepseek-ai/dsh-command-goal'],
  ['commands', '@deepseek-ai/dsh-commands'],
  ['compaction-basic', '@deepseek-ai/dsh-compaction-basic'],
  ['connection', '@deepseek-ai/dsh-client-connection'],
  ['cordis-client-runner', '@deepseek-ai/dsh-cordis-client-runner'],
  ['cordis-host-runner', '@deepseek-ai/dsh-cordis-host-runner'],
  ['credentials', '@deepseek-ai/dsh-credentials-local'],
  ['directory-picker', '@deepseek-ai/dsh-host-directory-picker-auto'],
  ['fs-observation-policy', '@deepseek-ai/dsh-fs-observation-policy'],
  ['fs-sandbox', '@deepseek-ai/dsh-fs-sandbox'],
  ['goal', '@deepseek-ai/dsh-goal'],
  ['goal-round-driver', '@deepseek-ai/dsh-goal-round-driver'],
  ['headless-runner', '@deepseek-ai/dsh-headless'],
  ['headless-startup', '@deepseek-ai/dsh-headless/startup'],
  ['hmr', '@deepseek-ai/cordis-plugin-hmr'],
  ['jobs', '@deepseek-ai/dsh-jobs-local'],
  ['llm', '@deepseek-ai/dsh-llm'],
  ['llm-deepseek', '@deepseek-ai/dsh-llm-deepseek'],
  ['llm-pi-ai', '@deepseek-ai/dsh-llm-pi-ai'],
  ['llm-retry', '@deepseek-ai/dsh-llm-retry'],
  ['locale', '@deepseek-ai/dsh-client-locale'],
  ['message-feedback', '@deepseek-ai/dsh-message-feedback'],
  ['modules', '@deepseek-ai/dsh-client-modules'],
  ['permission', '@deepseek-ai/dsh-permission-presets'],
  ['plan-mode', '@deepseek-ai/dsh-plan-mode'],
  ['plugin-inventory', '@deepseek-ai/dsh-host-plugin-inventory'],
  ['pwsh-sandbox', '@deepseek-ai/dsh-pwsh-sandbox'],
  ['repeat-tool-reminder', '@deepseek-ai/dsh-repeat-tool-reminder'],
  ['sandbox', '@deepseek-ai/dsh-sandbox-local'],
  ['sandbox-policy', '@deepseek-ai/dsh-sandbox-policy'],
  ['session', '@deepseek-ai/dsh-session'],
  ['session-checkpoint-policy', '@deepseek-ai/dsh-session-checkpoint-policy'],
  ['session-log-download', '@deepseek-ai/dsh-session-log-export'],
  ['session-persistence-jsonl', '@deepseek-ai/dsh-session-persistence-jsonl'],
  ['session-projection', '@deepseek-ai/dsh-session-projection'],
  ['session-projection-cache', '@deepseek-ai/dsh-session-projection-cache'],
  ['session-query-sqlite', '@deepseek-ai/dsh-session-query-sqlite'],
  ['session-stats', '@deepseek-ai/dsh-session-stats'],
  ['session-telemetry-otel', '@deepseek-ai/dsh-session-telemetry-otel'],
  ['session-title', '@deepseek-ai/dsh-session-title'],
  ['session-title-llm', '@deepseek-ai/dsh-session-title-first-prompt-llm'],
  ['settings', '@deepseek-ai/dsh-settings-file'],
  ['shell-env', '@deepseek-ai/dsh-shell-env'],
  ['skill', '@deepseek-ai/dsh-skill'],
  ['skill-badge', '@deepseek-ai/dsh-skill-badge'],
  ['skill-filesystem', '@deepseek-ai/dsh-skill-filesystem'],
  ['spill-local', '@deepseek-ai/dsh-spill-local'],
  ['spill-policy', '@deepseek-ai/dsh-spill-policy'],
  ['storage', '@deepseek-ai/dsh-storage'],
  ['storage-domain', '@deepseek-ai/dsh-storage-domain'],
  ['storage-json', '@deepseek-ai/dsh-storage-json'],
  ['subagent', '@deepseek-ai/dsh-subagent'],
  ['subagent-fork-in-process', '@deepseek-ai/dsh-subagent-fork-in-process'],
  ['subagent-spawn-in-process', '@deepseek-ai/dsh-subagent-spawn-in-process'],
  ['subprocess', '@deepseek-ai/dsh-subprocess-local'],
  ['system-prompt', '@deepseek-ai/dsh-system-prompt'],
  ['timeout-policy', '@deepseek-ai/dsh-tool-call-timeout-policy'],
  ['timer', '@deepseek-ai/cordis-plugin-timer'],
  ['token-meter', '@deepseek-ai/dsh-token-meter'],
  ['tool-bash', '@deepseek-ai/dsh-tool-bash'],
  ['tool-fs', '@deepseek-ai/dsh-tool-fs'],
  ['tool-fs-search', '@deepseek-ai/dsh-tool-fs-search'],
  ['tool-goal', '@deepseek-ai/dsh-tool-goal'],
  ['tool-jobs', '@deepseek-ai/dsh-tool-jobs'],
  ['tool-pwsh', '@deepseek-ai/dsh-tool-pwsh'],
  ['tool-ralph', '@deepseek-ai/dsh-tool-ralph'],
  ['tool-result-pruner', '@deepseek-ai/dsh-compaction-tool-result-pruner'],
  ['tool-skill', '@deepseek-ai/dsh-tool-skill'],
  ['tool-str-replace-editor', '@deepseek-ai/dsh-tool-str-replace-editor'],
  ['tool-subagent', '@deepseek-ai/dsh-tool-subagent'],
  ['tool-subagent-control', '@deepseek-ai/dsh-tool-subagent-control'],
  ['tool-subagent-fork', '@deepseek-ai/dsh-tool-subagent'],
  ['tool-subagent-list-agents', '@deepseek-ai/dsh-tool-subagent-control/list-agents'],
  ['tool-subagent-report', '@deepseek-ai/dsh-tool-subagent-report'],
  ['tool-todo', '@deepseek-ai/dsh-tool-todo'],
  ['tool-web', '@deepseek-ai/dsh-tool-web'],
  ['tool-workflow', '@deepseek-ai/dsh-tool-workflow'],
  ['tools', '@deepseek-ai/dsh-tools'],
  ['typert', '@deepseek-ai/dsh-typert-registry'],
  ['typert-gateway', '@deepseek-ai/dsh-api-gateway'],
  ['typert-loader', '@deepseek-ai/dsh-typert-loader'],
  ['ui-agent-preset', '@deepseek-ai/dsh-client-ui-agent-preset'],
  ['ui-commands', '@deepseek-ai/dsh-client-ui-commands'],
  ['ui-conversation', '@deepseek-ai/dsh-client-ui-conversation'],
  ['ui-cordis', '@deepseek-ai/dsh-client-ui-cordis'],
  ['ui-deliverables', '@deepseek-ai/dsh-client-ui-deliverables'],
  ['ui-goal', '@deepseek-ai/dsh-client-ui-goal'],
  ['ui-input-trigger', '@deepseek-ai/dsh-client-ui-input-trigger'],
  ['ui-jobs', '@deepseek-ai/dsh-client-ui-jobs'],
  ['ui-layout', '@deepseek-ai/dsh-client-ui-layout'],
  ['ui-message-feedback', '@deepseek-ai/dsh-client-ui-message-feedback'],
  ['ui-model-selection', '@deepseek-ai/dsh-client-ui-model-selection'],
  ['ui-permission', '@deepseek-ai/dsh-client-ui-permission-presets'],
  ['ui-plan', '@deepseek-ai/dsh-client-ui-plan'],
  ['ui-settings', '@deepseek-ai/dsh-client-ui-settings'],
  ['ui-settings-general', '@deepseek-ai/dsh-client-ui-settings-general'],
  ['ui-settings-models', '@deepseek-ai/dsh-client-ui-settings-models'],
  ['ui-settings-plugin-inventory', '@deepseek-ai/dsh-client-ui-settings-plugin-inventory'],
  ['ui-settings-plugins', '@deepseek-ai/dsh-client-ui-settings-plugins'],
  ['ui-sidebar', '@deepseek-ai/dsh-client-ui-sidebar'],
  ['ui-skill', '@deepseek-ai/dsh-client-ui-skill'],
  ['ui-subagent', '@deepseek-ai/dsh-client-ui-subagent'],
  ['ui-theme', '@deepseek-ai/dsh-client-ui-theme'],
  ['ui-tool', '@deepseek-ai/dsh-client-ui-tool'],
  ['ui-trajectory', '@deepseek-ai/dsh-client-ui-trajectory'],
  ['ui-user-questions', '@deepseek-ai/dsh-client-ui-user-questions'],
  ['ui-workflow-run', '@deepseek-ai/dsh-client-ui-workflow-run'],
  ['ui-workspace', '@deepseek-ai/dsh-client-ui-workspace'],
  ['user-questions', '@deepseek-ai/dsh-user-questions'],
  ['web', '@deepseek-ai/dsh-web'],
  ['web-runtime', '@deepseek-ai/dsh-web-app'],
  ['web-search-deepseek', '@deepseek-ai/dsh-web-search-deepseek'],
  ['web-startup', '@deepseek-ai/dsh-web-app/startup'],
  ['webserver', '@deepseek-ai/dsh-host-webserver'],
  ['workflow-worker-thread', '@deepseek-ai/dsh-workflow-worker-thread'],
  ['workspace', '@deepseek-ai/dsh-workspace'],
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
