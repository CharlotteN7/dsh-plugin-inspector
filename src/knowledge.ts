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
 * the shipped bundles' own `package.json`, which is `dsh`'s own version.
 *
 * Re-verified against `0.1.2-rc.1`, the release npm tags `latest`, by
 * extracting each table from the published packages and diffing it against the
 * one here. What moved: thirteen row ids the bundles gained against three they
 * dropped, four rows the base layer inserts that only the web bundle carried,
 * eleven seam keys against one dropped, and two waterfall events against one
 * dropped. What did not: the sandbox trap table, the teardown surfaces, and
 * every `DECISION_EVENT_DEFAULTS` citation, all re-read at this release.
 */
export const HARNESS_REFERENCE = '0.1.2-rc.1'

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
  ['api-remotes', { module: '@deepseek-ai/dsh-api-remotes', bundles: ['web-app'] }],
  ['approval', { module: '@deepseek-ai/dsh-user-approval', bundles: ['base'] }],
  ['attachment-local', { module: '@deepseek-ai/dsh-attachment-local', bundles: ['base'] }],
  ['bash-sandbox', { module: '@deepseek-ai/dsh-bash-sandbox', bundles: ['base'] }],
  ['client-hmr', { module: '@deepseek-ai/dsh-client-hmr', bundles: ['web-app'] }],
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
  ['deepseek-llm-api-extensions', { module: '@deepseek-ai/dsh-deepseek-llm-api-extensions', bundles: ['base'] }],
  ['directory-picker', { module: '@deepseek-ai/dsh-host-directory-picker-auto', bundles: ['web-app'] }],
  ['file-reference-local', { module: '@deepseek-ai/dsh-file-reference-local', bundles: ['web-app'] }],
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
  ['plugin-package-inventory-deepseek', { module: '@deepseek-ai/dsh-plugin-package-inventory-deepseek', bundles: ['base'] }],
  ['pwsh-sandbox', { module: '@deepseek-ai/dsh-pwsh-sandbox', bundles: ['base'] }],
  ['repeat-tool-reminder', { module: '@deepseek-ai/dsh-repeat-tool-reminder', bundles: ['base'] }],
  ['sandbox', { module: '@deepseek-ai/dsh-sandbox-local', bundles: ['base'] }],
  ['sandbox-policy', { module: '@deepseek-ai/dsh-sandbox-policy', bundles: ['base'] }],
  ['session', { module: '@deepseek-ai/dsh-session', bundles: ['base'] }],
  ['session-checkpoint-policy', { module: '@deepseek-ai/dsh-session-checkpoint-policy', bundles: ['base'] }],
  ['session-controller', { module: '@deepseek-ai/dsh-api-session-controller', bundles: ['web-app'] }],
  ['session-log-deepseek', { module: '@deepseek-ai/dsh-session-log-deepseek', bundles: ['base'] }],
  ['session-log-download', { module: '@deepseek-ai/dsh-session-log-export', bundles: ['web-app'] }],
  ['session-persistence-jsonl', { module: '@deepseek-ai/dsh-session-persistence-jsonl', bundles: ['base'] }],
  ['session-projection', { module: '@deepseek-ai/dsh-session-projection', bundles: ['base'] }],
  ['session-projection-cache', { module: '@deepseek-ai/dsh-session-projection-cache', bundles: ['base'] }],
  ['session-query-sqlite', { module: '@deepseek-ai/dsh-session-query-sqlite', bundles: ['base'] }],
  ['session-reference', { module: '@deepseek-ai/dsh-session-reference', bundles: ['web-app'] }],
  ['session-stats', { module: '@deepseek-ai/dsh-session-stats', bundles: ['web-app'] }],
  ['session-telemetry-otel', { module: '@deepseek-ai/dsh-session-telemetry-otel', bundles: ['base'] }],
  ['session-title', { module: '@deepseek-ai/dsh-session-title', bundles: ['base'] }],
  ['session-title-llm', { module: '@deepseek-ai/dsh-session-title-first-prompt-llm', bundles: ['base'] }],
  ['session-turn-outline', { module: '@deepseek-ai/dsh-session-turn-outline', bundles: ['web-app'] }],
  ['settings', { module: '@deepseek-ai/dsh-settings-file', bundles: ['base'] }],
  ['settings-controller', { module: '@deepseek-ai/dsh-api-settings-controller', bundles: ['web-app'] }],
  ['shell-env', { module: '@deepseek-ai/dsh-shell-env', bundles: ['base'] }],
  ['skill', { module: '@deepseek-ai/dsh-skill', bundles: ['base'] }],
  ['skill-badge', { module: '@deepseek-ai/dsh-skill-badge', bundles: ['base'] }],
  ['skill-filesystem', { module: '@deepseek-ai/dsh-skill-filesystem', bundles: ['base'] }],
  ['spill-local', { module: '@deepseek-ai/dsh-spill-local', bundles: ['base'] }],
  ['spill-policy', { module: '@deepseek-ai/dsh-spill-policy', bundles: ['base'] }],
  ['storage', { module: '@deepseek-ai/dsh-storage', bundles: ['base'] }],
  ['storage-domain', { module: '@deepseek-ai/dsh-storage-domain', bundles: ['base'] }],
  ['storage-json', { module: '@deepseek-ai/dsh-storage-json', bundles: ['base'] }],
  ['subagent', { module: '@deepseek-ai/dsh-subagent', bundles: ['base'] }],
  ['subagent-fork-in-process', { module: '@deepseek-ai/dsh-subagent-fork-in-process', bundles: ['base'] }],
  ['subagent-model-selection-settings', { module: '@deepseek-ai/dsh-tool-subagent/model-selection-settings', bundles: ['web-app'] }],
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
  ['tool-todo', { module: '@deepseek-ai/dsh-tool-todo', bundles: ['base'] }],
  ['tool-web', { module: '@deepseek-ai/dsh-tool-web', bundles: ['base'] }],
  ['tool-workflow', { module: '@deepseek-ai/dsh-tool-workflow', bundles: ['base'] }],
  ['tools', { module: '@deepseek-ai/dsh-tools', bundles: ['base'] }],
  ['typert', { module: '@deepseek-ai/dsh-typert-registry', bundles: ['base'] }],
  ['typert-gateway', { module: '@deepseek-ai/dsh-api-gateway', bundles: ['base'] }],
  ['typert-loader', { module: '@deepseek-ai/dsh-typert-loader', bundles: ['base'] }],
  ['ui-agent-preset', { module: '@deepseek-ai/dsh-client-ui-agent-preset', bundles: ['web-app'] }],
  ['ui-approval', { module: '@deepseek-ai/dsh-client-ui-approval', bundles: ['web-app'] }],
  ['ui-attachment', { module: '@deepseek-ai/dsh-client-ui-attachment', bundles: ['web-app'] }],
  ['ui-brand-official', { module: '@deepseek-ai/dsh-client-ui-brand-official', bundles: ['web-app'] }],
  ['ui-chat', { module: '@deepseek-ai/dsh-client-ui-chat', bundles: ['web-app'] }],
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
  ['ui-reference', { module: '@deepseek-ai/dsh-client-ui-reference', bundles: ['web-app'] }],
  ['ui-renderer', { module: '@deepseek-ai/dsh-client-ui-renderer', bundles: ['web-app'] }],
  ['ui-schedule', { module: '@deepseek-ai/dsh-client-ui-schedule', bundles: ['web-app'] }],
  ['ui-session', { module: '@deepseek-ai/dsh-client-ui-session', bundles: ['web-app'] }],
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
  ['web-fetch-http', { module: '@deepseek-ai/dsh-web-fetch-http', bundles: ['base'] }],
  ['web-runtime', { module: '@deepseek-ai/dsh-web-app', bundles: ['web-app'] }],
  ['web-search-deepseek', { module: '@deepseek-ai/dsh-web-search-deepseek', bundles: ['base'] }],
  ['web-startup', { module: '@deepseek-ai/dsh-web-app/startup', bundles: ['web-app'] }],
  ['webserver', { module: '@deepseek-ai/dsh-host-webserver', bundles: ['web-app'] }],
  ['workflow-worker-thread', { module: '@deepseek-ai/dsh-workflow-worker-thread', bundles: ['base'] }],
  ['workspace', { module: '@deepseek-ai/dsh-workspace', bundles: ['web-app'] }],
  ['workspace-controller', { module: '@deepseek-ai/dsh-api-workspace-controller', bundles: ['web-app'] }],
])

/** Row ids the shipped bundles define. */
export const CORE_ROW_IDS: ReadonlySet<string> = new Set(CORE_ROWS.keys())

/**
 * The core rows whose whole purpose is to constrain what the agent may do.
 * Disabling or reconfiguring one of these from a third-party patch layer is
 * the highest-value finding this tool produces, and it is plain YAML.
 *
 * Each entry names what stops holding when the row stops running. Membership
 * needs one of two properties: disabling the row **fails open**, so the agent
 * may afterwards do something it could not before, or it **removes evidence**
 * without saying so, leaving nothing to reconstruct what the agent did. A row
 * that fails closed on removal, or whose absence only takes a feature away, is
 * not a member however security-adjacent its name reads.
 *
 * The rows examined against that rule and kept out are listed with their
 * reasons under "What is deliberately not a finding" in `docs/checks.md`, so a
 * reader can tell a considered exclusion from a row nobody looked at.
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
  'agentDefaultModel', 'agentLoop', 'agentPresets', 'agents', 'agentTeams', 'approval', 'attachments',
  'authorization', 'clientModules', 'codeRuntime', 'commands', 'compaction', 'credentials',
  'credentialsController', 'deepseekLlmApiExtensions', 'directoryPicker', 'directoryPickerController',
  'e2b', 'fileReferences', 'fs', 'goals', 'inspector', 'invariants', 'jobs', 'llm', 'lsp',
  'messageFeedback', 'permissionPresets', 'planMode', 'sandbox', 'sandboxPolicy', 'sessionController',
  'sessionFileReferences', 'sessionPersistence', 'sessionProjectionCache', 'sessionProjections',
  'sessionQuery', 'sessionReferenceResolver', 'sessions', 'sessionSkillCatalog', 'sessionTelemetry',
  'sessionTitle', 'settings', 'settingsController', 'shell', 'shellEnv', 'skills', 'spillStore', 'storage',
  'storageDomain', 'subagentModelSelection', 'subagents', 'subprocess', 'systemPrompt', 'terminals',
  'timer', 'tokenMeter', 'toolResultPruner', 'tools', 'typert', 'typertGateway', 'userQuestions', 'web',
  'webhookRuntime', 'webServer', 'workflowEngine', 'workspaceController', 'workspaceRegistry',
])

/**
 * The subset of {@link SEAM_KEYS} whose replacement either removes a constraint
 * or takes over the record by which one could be checked afterwards. Most
 * members are the first kind — `approval`, `sandbox`, `credentials`. The set
 * already holds two of the second, `sessionPersistence` and `sessionTelemetry`,
 * and each entry below says which kind it is rather than borrowing the other's
 * sentence.
 *
 * `authorization` is the registry of flows that obtain a credential through a
 * conversation with the user, so providing it means owning that conversation.
 * That is the same class of substitution as `credentials`, which this set
 * already holds. `fileReferences` decides which paths are offered for
 * completion and `agentTeams` is the team form of `subagents`, which is
 * deliberately not here either, so neither of those is in this set.
 *
 * Seven of the eleven keys `0.1.2-rc.1` adds are Remote controllers: host
 * services that own one `ctx.remote.*` namespace the browser client calls
 * across the wire. A controller belongs here only when the traffic a
 * substitution redirects to it carries a secret, an execution boundary, or a
 * decision. A controller that forwards its seam's own verbs and adds a wire
 * failure vocabulary does not, because the seam it fronts is reachable from
 * `ctx` without substituting anything.
 *
 * Included:
 * - `credentialsController` is what a browser configuration page calls to store
 *   a credential. `set(ref, value)` receives the plaintext secret and hands it
 *   to `ctx.credentials`
 *   (`@deepseek-ai/dsh-api-settings-controller/lib/index.js:171`), and
 *   `projectCredentialInfo` at `lib/index.js:78` is what holds a `describe`
 *   answer to the three fields `CredentialInfo` declares. A layer that provides
 *   it takes both halves: every secret typed into the settings page, and the
 *   freedom to answer a read with the stored value.
 * - `settingsController` passes `redactSecrets: true` on every remote read
 *   (`@deepseek-ai/dsh-api-settings-controller/lib/index.js:429` and `:544`),
 *   which is what keeps a `role('secret')` field out of a settings response;
 *   `@deepseek-ai/dsh-web-search-deepseek/lib/index.js:245` declares one, an
 *   `apiKey`. Its `update`, `replace` and `mutate` verbs carry that same field's
 *   value in plaintext from the configuration page. Providing it puts the layer
 *   on both directions of a secret's path.
 * - `sessionController` resolves each new Session's cwd from the wire request
 *   and hands it to `ensureSession`
 *   (`@deepseek-ai/dsh-api-session-controller/lib/index.js:574`), and
 *   `@deepseek-ai/dsh-sandbox-policy` resolves that immutable cwd as the
 *   `workspace-write` root the enforcing filesystem, bash and terminal backends
 *   fence against. Its `prompt` verb builds the message admitted to the agent
 *   under `source.kind: 'user'` (`lib/index.js:731`). Providing it chooses the
 *   sandbox root for every session created from the client, and the text that
 *   reaches the model under the user's own source label.
 * - `webhookRuntime` is what a provider adapter such as
 *   `@deepseek-ai/dsh-webhook-github` dispatches verified deliveries into. Its
 *   one built-in action creates a Session from a rule result whose fields
 *   include `workspacePath`, `permissionPreset` and `prompt`
 *   (`@deepseek-ai/dsh-webhook/lib/types/types.d.ts`), and
 *   `createWebhookSession` applies that preset through
 *   `ctx.permissionPresets.set` before admitting the prompt
 *   (`@deepseek-ai/dsh-webhook/lib/types/session.js:94`, `:117`, `:120`).
 *   Providing it picks the approval and sandbox preset for an agent started by
 *   a remote delivery with no user present.
 * - `inspector` is the second kind, and the only member graded from the
 *   catalogue rather than from an implementation. The catalogue declares it as
 *   the façade over the realm's source publisher, with `publish(topic, payload,
 *   monotonicMs?)` and a read-only `CordisRuntimeTreeReader`
 *   (`@deepseek-ai/dsh-tool-cordis/lib/index.js:1558`, the two method
 *   signatures at `:1562` and `:1579`). Providing it
 *   takes no decision away from anyone: nothing is gated on an observation, and
 *   on that ground the key does not belong beside `approval`. What it takes is
 *   the position observations pass through. A substituted publisher chooses
 *   which topics reach the carrier and what payload each one carries, so it can
 *   withhold the record of something that happened or publish one for something
 *   that did not, and a consumer downstream cannot tell either from a quiet
 *   system. That is the property this set already recognises in
 *   `sessionPersistence` and `sessionTelemetry`.
 *
 *   No implementation exists to displace. In `0.1.2-rc.1` the key is declared
 *   once and used nowhere: `'inspector'` as a string literal occurs exactly
 *   once across the 224 `@deepseek-ai` packages in the installed tree — that
 *   catalogue entry — no file reads `ctx.inspector`, and `InspectorJsonValue`
 *   and `CordisRuntimeTreeReader` appear only in that same bundle. So a package
 *   providing `inspector` in this release displaces nothing and reaches nothing
 *   it could not reach under a name of its own. This entry grades what the
 *   catalogue says the key is for, not code that runs today, and it is the one
 *   entry a release that ships a publisher or a consumer should settle again
 *   against them.
 *
 * Excluded:
 * - `workspaceController` forwards `request.path` to
 *   `ctx.workspaceRegistry.create` unchanged and adds an ordering queue and
 *   error mapping (`@deepseek-ai/dsh-api-workspace-controller/lib/index.js:196`
 *   to `:212`). The registry it fronts is `workspaceRegistry`, which is not
 *   here, so the substitution reaches nothing the seam does not already offer.
 * - `directoryPickerController` is three delegations to
 *   `ctx.directoryPicker.capability()` behind a check that refuses a verb the
 *   composed backend does not serve
 *   (`@deepseek-ai/dsh-api-workspace-controller/lib/index.js:423` to `:470`).
 *   Path fencing lives in the backend, and `directoryPicker` is not here.
 * - `sessionFileReferences` is the Remote adapter over `fileReferences`, which
 *   is excluded above for the same reason: the traffic is path candidates
 *   offered for completion.
 * - `sessionSkillCatalog` answers with `SkillListValue`, declared as the list
 *   for one Session's human-facing composer
 *   (`@deepseek-ai/dsh-api-session-controller/lib/types/types.d.ts:213` to
 *   `:227`), and its only consumer in this release is the client skill picker
 *   (`@deepseek-ai/dsh-client-ui-skill/lib/client.js:236`). Skill text reaches a
 *   model through `ctx.skills.list()` in
 *   `@deepseek-ai/dsh-tool-skill/lib/index.js:145`, which is the `skills` seam.
 * - `subagentModelSelection` is a settings owner answering `{ enabled,
 *   allowedModels }`, sampled when an Agent receives its delegation tools. Model
 *   routing is `llm` and delegation is `subagents`; neither is here.
 * - `deepseekLlmApiExtensions` hands a substitute the serialized request body
 *   and merges the fields it returns, but
 *   `@deepseek-ai/dsh-llm-deepseek/lib/index.js:1748` rejects any extension
 *   field colliding with the base request, so `messages`, `tools` and `model`
 *   are not writable through it. The constraint is in the adapter, not the
 *   registry the substitution replaces.
 */
export const SECURITY_SEAM_KEYS: ReadonlySet<string> = new Set([
  'approval', 'authorization', 'sandbox', 'sandboxPolicy', 'permissionPresets', 'credentials',
  'credentialsController', 'settingsController', 'sessionController', 'webhookRuntime',
  'subprocess', 'shell', 'fs', 'tools', 'agentLoop', 'inspector', 'sessionPersistence',
  'sessionTelemetry', 'invariants',
])

/**
 * Waterfall events, from `EVENT_API` in the api-catalog. A listener on one of
 * these receives a trailing `next` and MUST call it to delegate; returning
 * without calling it short-circuits the chain including the built-in behavior.
 *
 * Note there is no `fs/read-intent` — the intent family is write and edit only.
 *
 * `0.1.2-rc.1` renames `tools/code-dispatch-log` to `tools/ptc-dispatch-log`
 * and adds `user-questions/request`. Both replace content in a durable log copy
 * or answer a pending request; neither is an `emit` event, so both hand a
 * listener the trailing `next`.
 */
export const WATERFALL_EVENTS: ReadonlySet<string> = new Set([
  'agent/pre-step', 'agent/request', 'agent/request-error', 'approval/request',
  'fs/edit-intent', 'fs/write-intent', 'llm/stream', 'session-telemetry/record',
  'system-prompt/assemble', 'tools/execute', 'tools/post-execute',
  'tools/pre-execute', 'tools/ptc-dispatch-log', 'user-questions/request',
])

/**
 * Waterfall events whose short-circuit removes a decision the user would
 * otherwise make.
 *
 * `user-questions/request` is here for the same reason `approval/request` is:
 * `ctx.userQuestions` pauses a tool call until a human answers, and the
 * answerers that put the question on a screen are listeners in the chain rather
 * than the inner callback (`@deepseek-ai/dsh-user-questions/lib/index.js:69`).
 * A listener that returns an answer without calling `next()` answers on the
 * user's behalf and the question is never shown.
 */
export const DECISION_EVENTS: ReadonlySet<string> = new Set([
  'approval/request', 'tools/pre-execute', 'tools/execute', 'fs/write-intent', 'fs/edit-intent',
  'user-questions/request',
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
  ['clearTimeout', "redirected to the cordis timer service (inject: ['timer'])"],
  ['clearInterval', "redirected to the cordis timer service (inject: ['timer'])"],
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

/** One thing a lifecycle command can do that a build never needs to. */
export interface LifecycleSignal {
  readonly id: string
  readonly pattern: RegExp
  /** What the match means, phrased for a report. */
  readonly meaning: string
}

/**
 * Command shapes that make an install lifecycle script the attack rather than
 * the build.
 *
 * The case this table is for is the one where the command line itself fetches,
 * decodes, or evaluates: the whole attack sits in `package.json` and there is
 * no shipped module to read. A lifecycle hook alone does not distinguish that
 * from a build, which is why the hook is a category at `medium` and only the
 * command raises it.
 *
 * Each pattern is chosen against the measured false-positive side rather than
 * against the idea of a build script. The five packages in the pinned corpus
 * that declare a hook run `tsdown`, `npm run build`, `husky`, and
 * `node scripts/prepare.mjs`; running a shipped file is what a build hook is, so
 * that shape is deliberately not a signal here.
 */
export const LIFECYCLE_SIGNALS: readonly LifecycleSignal[] = [
  {
    id: 'fetches-remote',
    pattern: /\b(?:curl|wget|Invoke-WebRequest|iwr)\b/i,
    meaning: 'fetches a remote resource at install time, so what runs is not what was published',
  },
  {
    id: 'pipes-to-shell',
    pattern: /\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/,
    meaning: 'pipes its input straight into a shell',
  },
  {
    id: 'evaluates-inline-code',
    pattern: /\b(?:node|deno|bun|ruby|perl)\s+(?:-\S+\s+)*--?e(?:val)?\b|\bpython3?\s+(?:-\S+\s+)*-c\b/,
    meaning: 'evaluates code written on the command line, which no published file records',
  },
  {
    id: 'decodes-payload',
    pattern: /\bbase64\s+(?:-d|-D|--decode)\b|\batob\s*\(|\bBuffer\.from\([^)]*base64/,
    meaning: 'decodes an encoded payload, which is how a command hides what it runs',
  },
]

/**
 * Every lifecycle signal a command line matches.
 *
 * One entry point rather than the filter written out twice, because the table
 * now grades two different things — a `package.json` lifecycle command (A1) and
 * a `binding.gyp` build step (A24) — and a rule added to it has to reach both.
 * @param command - the command line, or the text that holds one.
 * @returns the matching signals, in table order.
 */
export function matchingLifecycleSignals(command: string): LifecycleSignal[] {
  return LIFECYCLE_SIGNALS.filter(signal => signal.pattern.test(command))
}

/**
 * The file `node-gyp` reads, at the package root and nowhere else.
 *
 * npm and pnpm treat its presence as a declaration: a package that ships one
 * and declares no `install` or `preinstall` script gets `node-gyp rebuild` as
 * its install command. That default appears in no field of `package.json`.
 */
export const NATIVE_BUILD_FILE = 'binding.gyp'

/**
 * GYP keys that carry a command line rather than a list of sources to compile.
 *
 * `actions` and `rules` run a program during the build; `postbuilds` runs one
 * after it. A target that only lists `sources`, `include_dirs` and `libraries`
 * compiles code the package shipped and runs nothing else.
 *
 * Matched against the whole file, so a block nested inside a `conditions` arm
 * counts the same as a top-level one — which is the point, because a condition
 * is where a build step goes to be read past.
 */
export const GYP_COMMAND_KEYS = /['"](?:actions?|rules?|postbuilds)['"]\s*:/

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

/**
 * How a Cordis waterfall listener delegates, and what happens when it does not.
 *
 * Read out of the installed `@deepseek-ai/cordis@4.0.2` build,
 * `lib/index.js:317-327`:
 *
 * ```js
 * waterfall(...args) {
 *   const cbs = this.dispatch("waterfall", args);
 *   const inner = args.pop();
 *   const next = () => { return (cbs.shift() ?? inner)(...args); };
 *   args.push(next);
 *   return next();
 * }
 * ```
 *
 * `next` is the trailing argument every listener receives, and `inner` is the
 * harness's own built-in behavior. A listener that returns without calling
 * `next()` therefore ends the chain: neither the listeners still in `cbs` nor
 * `inner` run.
 *
 * The scope of that is one dispatch, not the registry. `dispatch()` builds
 * `cbs` with `.filter(…).map(…)`, which allocates, so `this._hooks[name]` is
 * never touched and every skipped listener is registered and runs normally on
 * the next dispatch. The precise word is veto, not removal — Cordis's own
 * JSDoc at `lib/index.js:311-313` says "vetoes the rest of the chain, including
 * the built-in behavior". Removal is a different capability with a different
 * reach, and it has its own table below.
 */
export const WATERFALL_NEXT_PARAMETER = 'next'

/**
 * What each decision waterfall's built-in `next` settles on when no listener
 * claims the dispatch, transcribed from the installed harness `0.1.2-rc.1`.
 *
 * This is what a listener that never calls `next()` replaces. The inner
 * callback is the last argument at each site:
 * - `tools/pre-execute` — `@deepseek-ai/dsh-tools/lib/index.js:3117`,
 *   `() => Promise.resolve({ kind: "allow" })`
 * - `tools/execute` — `dsh-tools/lib/index.js:3214`,
 *   `() => this.dispatchToolBody(mutableExec)`, so vetoing it substitutes the
 *   body of the tool call itself
 * - `approval/request` — `@deepseek-ai/dsh-user-approval/lib/index.js:179`,
 *   `() => Promise.resolve("unavailable")`, and the surface that would ask the
 *   user is one of the listeners in the chain rather than the inner callback
 * - `user-questions/request` —
 *   `@deepseek-ai/dsh-user-questions/lib/index.js:67`, the `noAnswerer`
 *   callback passed at `:69`, which rejects with a `UserQuestionError` carrying
 *   code `NO_PROVIDER`
 *
 * The three tables in this module that name events (`WATERFALL_EVENTS`,
 * `DECISION_EVENTS`, and this one) are keyed to {@link HARNESS_REFERENCE}.
 */
export const DECISION_EVENT_DEFAULTS: ReadonlyMap<string, string> = new Map([
  ['approval/request', 'the request falls through to `"unavailable"` only after every composed answerer — '
    + 'including the surface that would ask the user — has had the dispatch'],
  ['tools/pre-execute', 'the gate settles on `{ kind: "allow" }` after every other listener, and only then are '
    + '`ctx.tools.guard()` denials consulted'],
  ['tools/execute', 'the tool body itself runs'],
  ['fs/write-intent', 'the write intent reaches the policy rows that decide it'],
  ['fs/edit-intent', 'the edit intent reaches the policy rows that decide it'],
  ['user-questions/request', 'the request rejects with `NO_PROVIDER` only after every composed answerer — '
    + 'including the one that puts the question on the user\'s screen — has had the dispatch'],
])

/**
 * Receivers whose members name a plugin context.
 *
 * The same set the Tier C detached-member check guards on, minus `process`:
 * a seam is read off the context, never off `process`.
 */
export const CONTEXT_RECEIVERS: ReadonlySet<string> = new Set([
  'ctx', 'context', 'globalThis', 'global',
])

/**
 * Array and collection methods that change the receiver rather than reading it.
 *
 * Used to tell a write into a service's internals from a read of them. The
 * distinction is not academic: `dsh-dlp` reads
 * `ctx.events._hooks['approval/request']?.length` to decide whether an ask
 * would reach a human, which is an honest use of the same property a hostile
 * layer splices.
 */
export const MUTATING_METHODS: ReadonlySet<string> = new Set([
  'splice', 'push', 'pop', 'shift', 'unshift', 'fill', 'sort', 'reverse', 'copyWithin',
  'clear', 'delete', 'set', 'add',
])

/** One Cordis bookkeeping surface that owns other plugins' registrations. */
export interface TeardownSurface {
  /** The member read off the context, e.g. `events`. */
  readonly service: string
  /** The member read off that, e.g. `_hooks`. */
  readonly member: string
  /**
   * True when merely naming the surface is the finding. False when only a
   * write counts, because reading it is something an honest plugin does.
   */
  readonly readIsEnough: boolean
  /** What reaching it does, phrased for a report. */
  readonly effect: string
}

/**
 * Cordis internals through which one plugin removes another plugin's
 * registrations. Read from the installed `@deepseek-ai/cordis@4.0.2` build.
 *
 * None of these is guarded by ownership. `ctx.events`, `ctx.registry` and
 * `ctx.reflect` are own properties of the root context inherited by every
 * child, so no `inject` declaration is needed to reach any of them.
 */
export const TEARDOWN_SURFACES: readonly TeardownSurface[] = [
  {
    service: 'events',
    member: '_hooks',
    readIsEnough: false,
    effect: 'the listener table every layer\'s `ctx.on()` registration is stored in (`lib/index.js:230`, '
      + '`_hooks = {}`, appended to by `register` at `lib/index.js:336-345`). Splicing an entry out removes that '
      + 'listener permanently, and the owning layer\'s own disposer then silently does nothing. This is a stronger '
      + 'reach than a waterfall veto, which only skips listeners for one dispatch',
  },
  {
    service: 'events',
    member: 'unregister',
    readIsEnough: true,
    effect: 'the public removal path for one listener, by callback identity (`lib/index.js:353-359`). It takes the '
      + 'listener list and a callback and splices, with no check that the caller owns either',
  },
  {
    service: 'registry',
    member: 'delete',
    readIsEnough: true,
    effect: 'disposal of every fiber a plugin owns (`lib/index.js:1564-1571`: `for (const fiber of runtime.fibers) '
      + 'fiber.dispose();`). It takes no ownership check, so one layer can unload another layer outright — '
      + 'including a security layer whose guards and listeners then stop existing',
  },
  {
    service: 'reflect',
    member: 'store',
    readIsEnough: false,
    effect: 'the service implementation table keyed by isolate symbol (`lib/index.js:726`, written by `provide` at '
      + '`lib/index.js:813`). `provide` throws when a key is already taken and `set` throws across fibers; writing '
      + 'this object directly is the path around both throws',
  },
]
