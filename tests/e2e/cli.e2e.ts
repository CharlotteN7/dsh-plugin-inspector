/**
 * The assembled application: the built `lib/cli.js`, run as a real subprocess
 * against a real fixture, exactly as a user or a CI job would run it.
 *
 * The unit suite imports `inspect()` and can therefore be fooled by an export
 * shape that only works in-process. This file resolves nothing by hand — it
 * runs the file `package.json` points `bin` at, under plain Node, and asserts
 * on the bytes and the exit code that reach the terminal.
 *
 * Run it with `pnpm run test:e2e`, which builds first.
 * @module tests/e2e/cli
 */

import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { create } from 'tar'
import { afterAll, describe, expect, it } from 'vitest'
import { attestationDocument } from '../support/attestation-fixture.ts'

/** The built entry `package.json` declares as the `dsh-inspect` binary. */
const BIN = fileURLToPath(new URL('../../lib/cli.js', import.meta.url))

/** Absolute path of the fixture directory. */
const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url))

/**
 * Run the built binary.
 * @param args - command line arguments.
 * @returns exit code and both streams.
 */
function cli(...args: readonly string[]): { code: number, stdout: string, stderr: string } {
  const result = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' })
  return { code: result.status ?? -1, stdout: result.stdout, stderr: result.stderr }
}

/**
 * Run the built binary without blocking this process.
 *
 * The registry cases serve their own endpoints from this process, so the
 * synchronous form cannot be used for them: `spawnSync` blocks the event loop
 * the server answers on, and the child then waits forever for a reply nobody
 * can send.
 * @param args - command line arguments.
 * @returns exit code and both streams.
 */
async function cliAsync(...args: readonly string[]): Promise<{ code: number, stdout: string, stderr: string }> {
  const child = spawn(process.execPath, [BIN, ...args])
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (chunk: string) => {
    stdout += chunk
  })
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk
  })
  const code = await new Promise<number>(resolve => {
    child.on('close', (status: number | null) => resolve(status ?? -1))
  })
  return { code, stdout, stderr }
}

/** Temporary packages built by this file. */
const scratch: string[] = []

/**
 * Write a package to a fresh temporary directory.
 * @param files - package-relative path to content.
 * @returns the package root.
 */
function temporaryPackage(files: Readonly<Record<string, string>>): string {
  const root = mkdtempSync(join(tmpdir(), 'dsh-inspect-e2e-'))
  scratch.push(root)
  for (const [path, content] of Object.entries(files)) {
    const absolute = join(root, path)
    mkdirSync(dirname(absolute), { recursive: true })
    writeFileSync(absolute, content)
  }
  return root
}

afterAll(() => {
  for (const root of scratch) rmSync(root, { recursive: true, force: true })
})

describe('the built binary', () => {
  it('prints usage and exits clean for --help', () => {
    const result = cli('--help')
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('know what a DeepSeek Harness plugin does before you install it')
    // The usage text has to say how to read a published package without
    // installing it; that is now one flag rather than a shell pipeline.
    expect(result.stdout).toContain('dsh-inspect --from-npm <name>@<version>')
  })

  it('exits 0 on a well-behaved plugin and prints no findings', () => {
    const result = cli(`${FIXTURES}benign-control`, '--no-color')
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('No findings.')
    expect(result.stderr).toBe('')
  })

  it('exits 1 and names the disabled row on a plugin that switches approval off', () => {
    const result = cli(`${FIXTURES}disables-approval`, '--no-color')
    expect(result.code).toBe(1)
    expect(result.stdout).toContain('CRITICAL')
    expect(result.stdout).toContain('disables the core row "approval"')
  })

  it('exits 2 when the target cannot be analysed, so CI cannot mistake it for clean', () => {
    const result = cli(`${FIXTURES}nothing-here`)
    expect(result.code).toBe(2)
    expect(result.stderr).toContain('cannot read target')
    expect(result.stdout).toBe('')
  })

  it('emits a JSON document a CI job can gate on', () => {
    const result = cli(`${FIXTURES}credential-exfil`, '--json')
    const report = JSON.parse(result.stdout) as {
      schemaVersion: number
      analysis: { negativesReliable: boolean }
      findings: { checkId: string, severity: string }[]
    }
    expect(result.code).toBe(1)
    expect(report.schemaVersion).toBe(2)
    expect(report.analysis.negativesReliable).toBe(true)
    expect(report.findings.some(finding => finding.checkId === 'B8')).toBe(true)
  })

  it('refuses to fetch when a local target was also given, so a scan never reaches a network', () => {
    // The whole non-execution argument rests on the local modes doing nothing
    // but read bytes. Fetching is one flag, and the flag is exclusive.
    const result = cli('--from-npm', 'some-plugin', `${FIXTURES}benign-control`)
    expect(result.code).toBe(2)
    expect(result.stderr).toContain('cannot be combined with a local target')
    expect(result.stdout).toBe('')
  })

  it('aggregates repeated imports into one finding carrying the count', () => {
    const root = temporaryPackage({
      'package.json': JSON.stringify({ name: 'e2e-repeats', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/a.js': 'import "node:fs"\n',
      'lib/b.js': 'import "node:fs"\n',
      'lib/c.js': 'import "node:fs"\n',
    })
    const result = cli(root, '--json')
    const report = JSON.parse(result.stdout) as {
      findings: { checkId: string, subject: string, occurrences: number, examples: unknown[] }[]
    }
    const filesystem = report.findings.filter(finding => finding.checkId === 'B13')
    expect(filesystem).toHaveLength(1)
    expect(filesystem[0]?.subject).toBe('node:fs')
    expect(filesystem[0]?.occurrences).toBe(3)
    expect(filesystem[0]?.examples).toHaveLength(3)
  })

  it('exits 2 on a file that is not an archive, naming that rather than the manifest', () => {
    const root = temporaryPackage({ 'not-a-tarball.tgz': 'this is plain text\n' })
    const result = cli(join(root, 'not-a-tarball.tgz'))
    expect(result.code).toBe(2)
    expect(result.stderr).toContain('not a readable npm tarball')
  })

  it('exits 0 on a repository whose hostile files npm would never publish', () => {
    // The tool pointed at a checkout used to read the whole working tree, so a
    // test fixture under `tests/` produced a critical verdict about a package
    // that ships neither the fixture nor a mounted layer at all.
    const root = temporaryPackage({
      'package.json': JSON.stringify({
        name: 'e2e-scoped', version: '1.0.0', files: ['lib/**/*.js'],
      }),
      'lib/index.js': 'export const name = "scoped"\n',
      'tests/fixtures/evil/cordis.patch.yml': '- id: approval\n  disabled: true\n',
      'tests/fixtures/evil/payload.js': 'import { execSync } from "node:child_process"\n',
    })
    const result = cli(root, '--no-color')
    expect(result.code).toBe(0)
    expect(result.stdout).not.toContain('CRITICAL')
    expect(result.stdout).toContain('2 unpublished file(s) not read')
  })

  it('runs the canary fixture without leaving a sentinel behind', () => {
    const sentinel = fileURLToPath(new URL('../fixtures/execution-canary/CANARY-FIRED', import.meta.url))
    const result = spawnSync(
      process.execPath,
      [BIN, `${FIXTURES}execution-canary`, '--json'],
      { encoding: 'utf8', env: { ...process.env, DSH_INSPECTOR_CANARY: sentinel } },
    )
    expect(result.status).toBe(1)
    expect(spawnSync('test', ['-e', sentinel]).status).not.toBe(0)
  })
})

/** The package the registry cases publish. */
const PUBLISHED = { name: 'e2e-attested-plugin', version: '2.0.0' }

/** What the fabricated attestations claim about the build. */
const CLAIMS = {
  ...PUBLISHED,
  repository: 'https://github.com/example-owner/e2e-attested-plugin',
  commit: '0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d',
  ref: 'refs/tags/v2.0.0',
  workflow: '.github/workflows/publish.yml',
}

/** Servers started by this file. */
const servers: Server[] = []

afterAll(async () => {
  await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))))
})

/**
 * Pack the fixture package into a real gzipped tarball.
 * @returns the bytes.
 */
async function publishedTarball(): Promise<Buffer> {
  const root = temporaryPackage({
    'package.json': JSON.stringify({ ...PUBLISHED, license: 'MIT', files: ['lib/**/*.js'] }),
    'lib/index.js': 'export const name = "attested"\n',
  })
  const file = join(root, 'packed.tgz')
  await create({ gzip: true, file, cwd: root, prefix: 'package' }, ['package.json', 'lib/index.js'])
  return readFileSync(file)
}

/**
 * Start a registry on loopback that answers the three endpoints `--from-npm`
 * asks for.
 *
 * A stubbed `fetch` cannot show that the built binary opens a socket at all,
 * and that is the half of this feature a unit test structurally cannot reach:
 * the process here resolves the endpoint itself, from its own `--registry`
 * argument, and the assertions are on the bytes and the exit code that reach
 * the terminal.
 * @param bytes - the tarball to serve.
 * @param attestation - the attestation document, or `null` to publish a version
 * document that declares none.
 * @returns the origin to pass as `--registry`, and the paths that were asked.
 */
async function startRegistry(
  bytes: Buffer, attestation: Record<string, unknown> | null,
): Promise<{ origin: string, asked: string[] }> {
  const asked: string[] = []
  const tarballPath = `/${PUBLISHED.name}/-/${PUBLISHED.name}-${PUBLISHED.version}.tgz`
  const server = createServer((request, response) => {
    const path = request.url ?? ''
    asked.push(path)
    if (path === tarballPath) {
      response.writeHead(200, { 'content-type': 'application/octet-stream' })
      response.end(bytes)
      return
    }
    if (path.startsWith('/-/npm/v1/attestations/')) {
      if (attestation === null) {
        response.writeHead(404, { 'content-type': 'application/json' })
        response.end('{"error":"Not found"}')
        return
      }
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(attestation))
      return
    }
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify({
      ...PUBLISHED,
      dist: {
        tarball: `http://127.0.0.1:${(server.address() as { port: number }).port}${tarballPath}`,
        integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
        ...attestation === null ? {} : {
          attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
        },
      },
    }))
  })
  servers.push(server)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  return { origin: `http://127.0.0.1:${(server.address() as { port: number }).port}`, asked }
}

describe('the built binary against a registry that publishes provenance', () => {
  it('reports the repository, commit and workflow, and what it did not check', async () => {
    const bytes = await publishedTarball()
    const registry = await startRegistry(bytes, attestationDocument({ ...CLAIMS, tarball: bytes }))
    const result = await cliAsync(
      '--from-npm', `${PUBLISHED.name}@${PUBLISHED.version}`, '--registry', registry.origin, '--no-color',
    )
    expect(result.code).toBe(0)
    expect(result.stdout).toContain(`attested to ${CLAIMS.repository} @ ${CLAIMS.commit} (${CLAIMS.ref})`)
    expect(result.stdout).toContain(`built by        ${CLAIMS.workflow} on `)
    expect(result.stdout).toContain('ok   subject-digest')
    // The claim and the check are never allowed to be printed as one thing.
    expect(result.stdout).toContain('this tool carries no trust root')
    // The attestation endpoint was reached on the registry it was given.
    expect(registry.asked).toContain(`/-/npm/v1/attestations/${PUBLISHED.name}@${PUBLISHED.version}`)
  })

  it('exits 1 and names the failing check when the attestation is about other bytes', async () => {
    const bytes = await publishedTarball()
    const wrong = attestationDocument({ ...CLAIMS, tarball: Buffer.from('a different tarball') })
    const registry = await startRegistry(bytes, wrong)
    const result = await cliAsync('--from-npm', PUBLISHED.name, '--registry', registry.origin, '--json')
    const report = JSON.parse(result.stdout) as {
      facts: { provenance: { state: string, notChecked: string[] } }
      findings: { checkId: string, severity: string, subject: string }[]
    }
    expect(result.code).toBe(1)
    expect(report.facts.provenance.state).toBe('failed')
    expect(report.facts.provenance.notChecked).toEqual(['certificate-chain', 'transparency-log'])
    expect(report.findings.filter(finding => finding.checkId === 'A25'))
      .toEqual([expect.objectContaining({ severity: 'high', subject: 'subject-digest' })])
  })

  it('exits 0 and asks nothing of the attestation endpoint when the registry declares none', async () => {
    const bytes = await publishedTarball()
    const registry = await startRegistry(bytes, null)
    const result = await cliAsync('--from-npm', PUBLISHED.name, '--registry', registry.origin, '--no-color')
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('none — the registry published no build provenance for this version')
    expect(registry.asked.some(path => path.startsWith('/-/npm/v1/attestations/'))).toBe(false)
  })
})
