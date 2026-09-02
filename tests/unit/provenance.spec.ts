/**
 * npm provenance: reading the registry's signed statement about where a
 * tarball was built, and keeping "the registry told me a claim exists" apart
 * from "I checked the claim".
 *
 * Nothing here reaches a network — `fetch` is injected, exactly as in
 * `registry.spec.ts`. The bundles are signed by the fixture under its own
 * self-signed certificate, which is possible only because this tool does not
 * chain the certificate to a trust root; the cases below assert that the report
 * says so in the same breath as it reports what did check out.
 * @module tests/unit/provenance
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { afterAll, describe, expect, it } from 'vitest'
import {
  packageUrl,
  provenanceUnavailable,
  readProvenance,
  type ProvenanceFact,
} from '../../src/attestation.ts'
import { inspect } from '../../src/inspect.ts'
import { inspectFromNpm } from '../../src/npm.ts'
import { attestationUrl, RegistryError } from '../../src/registry.ts'
import { renderHuman, renderJson } from '../../src/report.ts'
import { attestationDocument, issueCertificate, statement } from '../support/attestation-fixture.ts'
import { cleanupPackages, createPackage, packExactly } from './package-fixture.ts'

afterAll(cleanupPackages)

/** The registry every test in this file pretends to talk to. */
const REGISTRY = 'https://registry.npmjs.org'

/** The package the fixtures publish. */
const NAME = 'attested-plugin'

/** The version the fixtures publish. */
const VERSION = '1.4.0'

/** The endpoint the tool builds for that package. */
const ATTESTATION = `${REGISTRY}/-/npm/v1/attestations/${NAME}@${VERSION}`

/** A minimal but complete plugin package. */
const FILES = {
  'package.json': JSON.stringify({ name: NAME, version: VERSION, license: 'MIT', files: ['lib/**/*.js'] }),
  'lib/index.js': 'export const name = "attested"\n',
}

/** What the fixtures claim about the build, unless a case changes one field. */
const CLAIMS = {
  name: NAME,
  version: VERSION,
  repository: 'https://github.com/example-owner/attested-plugin',
  commit: '9f2c1b0d4e6a8c1f3b5d7e9a0c2e4f6a8b0d2c4e',
  ref: 'refs/tags/v1.4.0',
  workflow: '.github/workflows/publish.yml',
}

/**
 * Build a real npm-shaped tarball in memory.
 * @returns the gzipped tarball bytes.
 */
async function tarball(): Promise<Buffer> {
  const root = createPackage(FILES)
  return readFileSync(await packExactly(root, Object.keys(FILES)))
}

/** How a stub registry should answer the attestation endpoint. */
type Attestation = { body: string, status?: number } | 'declare-none'

/**
 * A `fetch` answering the three endpoints `--from-npm` can ask for, recording
 * every one so a case can assert which were asked and in what order.
 * @param bytes - the tarball to serve.
 * @param attestation - what to serve for the attestation endpoint, or
 * `declare-none` to publish a version document that claims no attestation.
 * @returns the stub and the URLs it was asked for.
 */
function registryStub(bytes: Buffer, attestation: Attestation): {
  fetch: typeof globalThis.fetch
  calls: string[]
} {
  const calls: string[] = []
  const url = `${REGISTRY}/${NAME}/-/${NAME}-${VERSION}.tgz`
  const document = {
    name: NAME,
    version: VERSION,
    dist: {
      tarball: url,
      integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
      ...attestation === 'declare-none' ? {} : {
        attestations: { url: 'https://elsewhere.test/ignored', provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
      },
    },
  }
  const stub = ((asked: string | URL): Promise<Response> => {
    const href = String(asked)
    calls.push(href)
    if (href === url) return Promise.resolve(new Response(new Uint8Array(bytes), { status: 200 }))
    if (href.includes('/attestations/')) {
      if (attestation === 'declare-none') return Promise.resolve(new Response('{"error":"Not found"}', { status: 404 }))
      return Promise.resolve(new Response(attestation.body, { status: attestation.status ?? 200 }))
    }
    return Promise.resolve(new Response(JSON.stringify(document), { status: 200 }))
  }) as unknown as typeof globalThis.fetch
  return { fetch: stub, calls }
}

/**
 * Inspect the fixture package with a stub registry serving one attestation.
 * @param bytes - the tarball to serve.
 * @param attestation - what to serve for the attestation endpoint.
 * @returns the provenance fact from the resulting report, and the URLs asked.
 */
async function fetchFact(bytes: Buffer, attestation: Attestation): Promise<{
  provenance: ProvenanceFact
  calls: string[]
  findings: readonly { checkId: string, severity: string, subject: string }[]
}> {
  const stub = registryStub(bytes, attestation)
  const report = await inspectFromNpm(`${NAME}@${VERSION}`, { fetch: stub.fetch })
  return { provenance: report.facts.provenance, calls: stub.calls, findings: report.findings }
}

/**
 * Serialise a fabricated attestation document.
 * @param document - the document.
 * @returns the body to serve.
 */
function serve(document: Record<string, unknown>): { body: string } {
  return { body: JSON.stringify(document) }
}

describe('a target that has no registry statement at all', () => {
  it('says the mode cannot read one rather than reporting an absence', async () => {
    const report = await inspect(createPackage(FILES))
    expect(report.facts.provenance.state).toBe('unavailable')
    expect(report.facts.provenance.attestationUrl).toBeNull()
    expect(renderHuman(report, false)).toContain('not readable here — a directory or local tarball')
    // The distinction is the point: a directory saying "no provenance" would be
    // a statement about the package, and this is a statement about the mode.
    expect(renderHuman(report, false)).not.toContain('the registry published no build provenance')
  })

  it('reports the same for a tarball on disk', async () => {
    const root = createPackage(FILES)
    const report = await inspect(await packExactly(root, Object.keys(FILES)))
    expect(report.facts.provenance.state).toBe('unavailable')
  })

  it('carries the fact into the JSON document, so a consumer never has to infer it', async () => {
    const report = await inspect(createPackage(FILES))
    const parsed = JSON.parse(renderJson(report)) as { facts: { provenance: ProvenanceFact } }
    expect(parsed.facts.provenance).toEqual(provenanceUnavailable())
  })
})

describe('a published package the registry says has no attestation', () => {
  it('reports the absence and asks the attestation endpoint nothing', async () => {
    const bytes = await tarball()
    const result = await fetchFact(bytes, 'declare-none')
    expect(result.provenance.state).toBe('absent')
    expect(result.provenance.reason).toBeNull()
    // Two requests, not three. Most published packages have no attestation, so
    // reading the version document first is what keeps this free for them.
    expect(result.calls).toEqual([
      `${REGISTRY}/${NAME}/${VERSION}`,
      `${REGISTRY}/${NAME}/-/${NAME}-${VERSION}.tgz`,
    ])
  })

  it('raises nothing: 28 of the 40 pinned packages are in exactly this state', async () => {
    const bytes = await tarball()
    const result = await fetchFact(bytes, 'declare-none')
    expect(result.findings.filter(finding => finding.checkId === 'A25')).toEqual([])
  })
})

describe('an attestation that checks out', () => {
  it('names the repository, commit and workflow, and says which checks ran', async () => {
    const bytes = await tarball()
    const result = await fetchFact(bytes, serve(attestationDocument({ ...CLAIMS, tarball: bytes })))
    expect(result.provenance.state).toBe('attested')
    expect(result.provenance.sourceRepository).toBe(CLAIMS.repository)
    expect(result.provenance.sourceCommit).toBe(CLAIMS.commit)
    expect(result.provenance.sourceRef).toBe(CLAIMS.ref)
    expect(result.provenance.workflow).toBe(CLAIMS.workflow)
    expect(result.provenance.builder).toBe('https://github.com/actions/runner/github-hosted')
    expect(result.provenance.checks.map(check => [check.name, check.passed])).toEqual([
      ['subject-digest', true],
      ['subject-package', true],
      ['dsse-signature', true],
      ['certificate-identity', true],
    ])
  })

  it('reads the endpoint it builds itself, not the one the version document names', async () => {
    const bytes = await tarball()
    const result = await fetchFact(bytes, serve(attestationDocument({ ...CLAIMS, tarball: bytes })))
    // The stub's `dist.attestations.url` points at another host entirely. A
    // doctored packument cannot redirect this request, because the request is
    // not built from the packument.
    expect(result.calls[2]).toBe(ATTESTATION)
    expect(result.calls.some(call => call.includes('elsewhere.test'))).toBe(false)
  })

  it('reads the 0.2 bundle shape as well as the 0.3 one, because npm publishes both', async () => {
    const bytes = await tarball()
    const chain = serve(attestationDocument({ ...CLAIMS, tarball: bytes }, { mediaType: 'v0.2' }))
    expect((await fetchFact(bytes, chain)).provenance.state).toBe('attested')
  })

  it('never calls it verified: the certificate is not chained to anything', async () => {
    const bytes = await tarball()
    const stub = registryStub(bytes, serve(attestationDocument({ ...CLAIMS, tarball: bytes })))
    const report = await inspectFromNpm(`${NAME}@${VERSION}`, { fetch: stub.fetch })
    expect(report.facts.provenance.notChecked).toEqual(['certificate-chain', 'transparency-log'])
    const text = renderHuman(report, false)
    // The fixture's certificate is self-signed. It passes every check this tool
    // runs, which is the whole reason the report has to print the gap.
    expect(text).toContain('not checked')
    expect(text).toContain('this tool carries no trust root')
    expect(text).toContain('Rekor transparency-log inclusion proof')
  })

  it('raises no finding', async () => {
    const bytes = await tarball()
    const result = await fetchFact(bytes, serve(attestationDocument({ ...CLAIMS, tarball: bytes })))
    expect(result.findings.filter(finding => finding.checkId === 'A25')).toEqual([])
  })
})

describe('an attestation that does not check out', () => {
  it('fails the digest check when the statement covers other bytes, and raises A25', async () => {
    const bytes = await tarball()
    const other = serve(attestationDocument({ ...CLAIMS, tarball: Buffer.from('a different tarball') }))
    const result = await fetchFact(bytes, other)
    expect(result.provenance.state).toBe('failed')
    expect(result.provenance.checks.find(check => check.name === 'subject-digest')?.passed).toBe(false)
    const raised = result.findings.filter(finding => finding.checkId === 'A25')
    expect(raised).toHaveLength(1)
    expect(raised[0]?.severity).toBe('high')
    expect(raised[0]?.subject).toBe('subject-digest')
  })

  it('fails the package check when the statement is about another package', async () => {
    const bytes = await tarball()
    const document = serve(attestationDocument({ ...CLAIMS, name: 'some-other-plugin', tarball: bytes }))
    const result = await fetchFact(bytes, document)
    expect(result.provenance.state).toBe('failed')
    expect(result.provenance.checks.find(check => check.name === 'subject-package')?.detail)
      .toContain(`not ${packageUrl(NAME, VERSION)}`)
    expect(result.findings.filter(finding => finding.checkId === 'A25')[0]?.subject).toBe('subject-package')
  })

  it('fails the signature check when the envelope was signed over another statement', async () => {
    const bytes = await tarball()
    const document = serve(attestationDocument(
      { ...CLAIMS, tarball: bytes },
      { signInstead: statement({ ...CLAIMS, name: 'other', tarball: bytes }) },
    ))
    const result = await fetchFact(bytes, document)
    expect(result.provenance.checks.find(check => check.name === 'dsse-signature'))
      .toEqual({
        name: 'dsse-signature',
        detail: 'the DSSE signature does not verify under the public key of the certificate in the bundle',
        passed: false,
      })
  })

  it('fails the identity check when the certificate names a workflow the statement does not', async () => {
    const bytes = await tarball()
    const document = serve(attestationDocument(
      { ...CLAIMS, tarball: bytes },
      { identity: 'https://github.com/someone-else/fork/.github/workflows/publish.yml@refs/heads/main' },
    ))
    const result = await fetchFact(bytes, document)
    expect(result.provenance.checks.find(check => check.name === 'certificate-identity')?.passed).toBe(false)
    expect(result.provenance.signerIdentity).toContain('someone-else/fork')
  })

  it('reports a signature it could not check at all as a failure, not as a crash', async () => {
    const bytes = await tarball()
    const document = serve(attestationDocument({ ...CLAIMS, tarball: bytes }, { keyType: 'ed25519' }))
    const result = await fetchFact(bytes, document)
    expect(result.provenance.checks.find(check => check.name === 'dsse-signature')?.detail)
      .toContain('the signature could not be checked against the bundle\'s certificate')
  })

  it('says so in the human report in words nobody can read as a pass', async () => {
    const bytes = await tarball()
    const stub = registryStub(bytes, serve(attestationDocument({ ...CLAIMS, tarball: Buffer.from('other') })))
    const text = renderHuman(await inspectFromNpm(`${NAME}@${VERSION}`, { fetch: stub.fetch }), false)
    expect(text).toContain('AND THE ATTESTATION DOES NOT CHECK OUT')
    expect(text).toContain('FAIL subject-digest')
  })
})

describe('a statement this tool cannot read every claim out of', () => {
  it('skips the identity check and says which claim it therefore did not establish', async () => {
    const bytes = await tarball()
    const bare = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{
        name: packageUrl(NAME, VERSION),
        digest: { sha512: createHash('sha512').update(bytes).digest('hex') },
      }],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: { buildDefinition: { buildType: 'https://example.test/gitlab/v1' } },
    }
    const result = await fetchFact(bytes, serve(attestationDocument({ ...CLAIMS, tarball: bytes }, { payload: bare })))
    expect(result.provenance.state).toBe('attested')
    expect(result.provenance.checks.map(check => check.name))
      .toEqual(['subject-digest', 'subject-package', 'dsse-signature'])
    expect(result.provenance.notChecked).toContain('builder-identity')
    expect(result.provenance.sourceRepository).toBeNull()
    expect(result.provenance.sourceCommit).toBeNull()
    expect(result.provenance.builder).toBeNull()
  })

  it('renders a statement with no workflow without inventing one', async () => {
    const bytes = await tarball()
    const bare = { predicateType: 'https://slsa.dev/provenance/v1', subject: [] }
    const stub = registryStub(bytes, serve(attestationDocument({ ...CLAIMS, tarball: bytes }, { payload: bare })))
    const text = renderHuman(await inspectFromNpm(`${NAME}@${VERSION}`, { fetch: stub.fetch }), false)
    expect(text).toContain('an unnamed repository')
    expect(text).toContain('an unnamed workflow')
    expect(text).toContain('names no GitHub Actions workflow')
  })

  it('names an unnamed subject rather than dropping it', () => {
    const bytes = Buffer.from('bytes')
    const document = attestationDocument({ ...CLAIMS, tarball: bytes }, {
      payload: {
        predicateType: 'https://slsa.dev/provenance/v1',
        subject: [{ digest: { sha512: createHash('sha512').update(bytes).digest('hex') } }],
      },
    })
    const fact = readProvenance(Buffer.from(JSON.stringify(document)), {
      name: NAME, version: VERSION, tarball: bytes, url: ATTESTATION,
    })
    expect(fact.checks.find(check => check.name === 'subject-package')?.detail).toContain('the statement names (unnamed)')
  })

  it('says "no subject" when the statement covers nothing', () => {
    const bytes = Buffer.from('bytes')
    const document = attestationDocument({ ...CLAIMS, tarball: bytes }, {
      payload: { predicateType: 'https://slsa.dev/provenance/v1' },
    })
    const fact = readProvenance(Buffer.from(JSON.stringify(document)), {
      name: NAME, version: VERSION, tarball: bytes, url: ATTESTATION,
    })
    expect(fact.checks.find(check => check.name === 'subject-package')?.detail).toContain('names no subject')
  })

  it('records no signer identity when the certificate carries none', () => {
    const bytes = Buffer.from('bytes')
    const document = attestationDocument({ ...CLAIMS, tarball: bytes }, { identity: null })
    const fact = readProvenance(Buffer.from(JSON.stringify(document)), {
      name: NAME, version: VERSION, tarball: bytes, url: ATTESTATION,
    })
    expect(fact.signerIdentity).toBeNull()
    expect(fact.checks.find(check => check.name === 'certificate-identity')?.detail)
      .toContain('the signing certificate names nothing')
  })
})

describe('an attestation document that cannot be read at all', () => {
  /**
   * Read one unreadable document and return why it was unreadable.
   * @param body - what the endpoint served.
   * @returns the fact.
   */
  const unreadable = async (body: string): Promise<ProvenanceFact> =>
    (await fetchFact(await tarball(), { body })).provenance

  it('is not an absence, and not a refusal to analyse the package', async () => {
    const bytes = await tarball()
    const result = await fetchFact(bytes, { body: 'not found', status: 503 })
    expect(result.provenance.state).toBe('unreadable')
    expect(result.provenance.reason).toContain('returned HTTP 503')
    expect(result.provenance.attestationUrl).toBe(ATTESTATION)
    // The tarball was still verified and analysed: provenance is a fact about
    // the package, never a precondition for reading it.
    expect(result.findings.filter(finding => finding.checkId === 'A25')).toEqual([])
  })

  it('prints the reason where a pass would have printed the repository', async () => {
    const bytes = await tarball()
    const stub = registryStub(bytes, { body: '{"error":"Not found"}', status: 404 })
    const text = renderHuman(await inspectFromNpm(`${NAME}@${VERSION}`, { fetch: stub.fetch }), false)
    expect(text).toContain('the registry says this version has one and it could not be read')
    expect(text).toContain('returned HTTP 404')
    expect(text).not.toContain('attested to')
  })

  it('names each thing that was wrong with the document', async () => {
    expect((await unreadable('<html>502</html>')).reason).toContain('did not return JSON')
    expect((await unreadable('{"attestations":7}')).reason).toContain('carries no https://slsa.dev/provenance/v1')
    expect((await unreadable(JSON.stringify({
      attestations: [{ predicateType: 'https://slsa.dev/provenance/v1', bundle: {} }],
    }))).reason).toContain('carries no signing certificate')
    expect((await unreadable(JSON.stringify({
      attestations: [{
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: { verificationMaterial: { x509CertificateChain: { certificates: 'not a list' } } },
      }],
    }))).reason).toContain('carries no signing certificate')
    expect((await unreadable(JSON.stringify({
      attestations: [{
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: { verificationMaterial: { x509CertificateChain: { certificates: [{}] } } },
      }],
    }))).reason).toContain('carries no signing certificate')
    expect((await unreadable(JSON.stringify({
      attestations: [{
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: { verificationMaterial: { certificate: { rawBytes: 'bm90IGEgY2VydGlmaWNhdGU=' } } },
      }],
    }))).reason).toContain('signing certificate does not parse')
  })

  it('refuses a bundle whose envelope is incomplete, field by field', async () => {
    const rawBytes = issueCertificate('https://example.test/w.yml@refs/heads/main').certificate.toString('base64')
    /**
     * A document whose provenance bundle carries the envelope given.
     * @param dsseEnvelope - the envelope, complete or not.
     * @returns the body to serve.
     */
    const withEnvelope = (dsseEnvelope: Record<string, unknown>): string => JSON.stringify({
      attestations: [{
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: { verificationMaterial: { certificate: { rawBytes } }, dsseEnvelope },
      }],
    })
    const payload = Buffer.from('{}').toString('base64')
    const payloadType = 'application/vnd.in-toto+json'
    const signatures = [{ sig: 'AAAA' }]
    expect((await unreadable(withEnvelope({ payloadType, signatures }))).reason).toContain('no complete DSSE envelope')
    expect((await unreadable(withEnvelope({ payload, signatures }))).reason).toContain('no complete DSSE envelope')
    expect((await unreadable(withEnvelope({ payload, payloadType }))).reason).toContain('no complete DSSE envelope')
    expect((await unreadable(withEnvelope({ payload, payloadType, signatures: [{}] })))
      .reason).toContain('no complete DSSE envelope')
    expect((await unreadable(withEnvelope({
      payload: Buffer.from('not json').toString('base64'), payloadType, signatures,
    }))).reason).toContain('signed statement is not JSON')
  })

  it('refuses a document larger than the ceiling instead of holding it', async () => {
    const bytes = await tarball()
    const stub = registryStub(bytes, serve(attestationDocument({ ...CLAIMS, tarball: bytes })))
    const flooding = ((asked: string | URL): Promise<Response> => {
      if (String(asked).includes('/attestations/')) {
        return Promise.resolve(new Response(new ReadableStream<Uint8Array>({
          pull(controller) {
            controller.enqueue(new Uint8Array(256 * 1024))
          },
        }), { status: 200 }))
      }
      return stub.fetch(asked) as Promise<Response>
    }) as unknown as typeof globalThis.fetch
    const report = await inspectFromNpm(`${NAME}@${VERSION}`, { fetch: flooding })
    expect(report.facts.provenance.state).toBe('unreadable')
    expect(report.facts.provenance.reason).toContain('attestation document is larger than')
  })
})

describe('the endpoint the tool builds', () => {
  it('is on the registry it was given, honouring --registry', () => {
    expect(attestationUrl('https://npm.internal.test', '@scope/thing', '0.1.0'))
      .toBe('https://npm.internal.test/-/npm/v1/attestations/@scope/thing@0.1.0')
  })

  it('refuses a name or version out of the version document that would address something else', () => {
    // Both come out of a registry-controlled document and are interpolated into
    // a URL, which makes them a wire boundary however the spec was typed.
    expect(() => attestationUrl(REGISTRY, '../../evil', '1.0.0')).toThrow(RegistryError)
    expect(() => attestationUrl(REGISTRY, NAME, '../../evil')).toThrow(/names no version/)
  })

  it('leaves the provenance unreadable rather than failing when the document names neither', async () => {
    const bytes = await tarball()
    const doctored = ((asked: string | URL): Promise<Response> => {
      const href = String(asked)
      if (href.endsWith('.tgz')) return Promise.resolve(new Response(new Uint8Array(bytes), { status: 200 }))
      return Promise.resolve(new Response(JSON.stringify({
        name: 'not a package name/../..',
        version: VERSION,
        dist: {
          tarball: `${REGISTRY}/x/-/x-1.0.0.tgz`,
          integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
          attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
        },
      }), { status: 200 }))
    }) as unknown as typeof globalThis.fetch
    const report = await inspectFromNpm(NAME, { fetch: doctored })
    expect(report.facts.provenance.state).toBe('unreadable')
    expect(report.facts.provenance.attestationUrl).toBeNull()
    expect(report.facts.provenance.reason).toContain('names no npm package')
  })
})
