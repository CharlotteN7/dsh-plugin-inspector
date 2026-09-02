/**
 * npm provenance attestations: what the registry says about where a published
 * tarball was built, and how much of that this tool can check for itself.
 *
 * A provenance attestation is a Sigstore bundle holding a DSSE envelope over an
 * in-toto statement. The statement names the tarball by digest and, for a
 * GitHub Actions build, the source repository, the commit, and the workflow
 * file that produced it. npm publishes one when a package is released from a
 * trusted CI environment.
 *
 * **This module is careful about the difference between reading a claim and
 * checking one, because a reader who confuses them is worse off than one who
 * has neither.** Everything it can check runs offline against bytes already in
 * hand, and everything it cannot check is named in the same record:
 *
 * - `subject-digest` — the statement's subject digest is the SHA-512 of the
 *   tarball this run analysed. This is the binding that makes the rest mean
 *   anything: without it the attestation could be about another version.
 * - `subject-package` — that subject is this package at this version, written
 *   as a package URL.
 * - `dsse-signature` — the envelope's signature verifies under the public key
 *   of the certificate carried inside the bundle.
 * - `certificate-identity` — the certificate's subject alternative name is the
 *   workflow the statement claims built the package, so payload and signer
 *   agree.
 *
 * What it does **not** do is establish that the certificate is Sigstore's. That
 * needs the Fulcio root, which lives in the Sigstore trust root and not on any
 * npm registry, and the same root is what a Rekor inclusion proof is checked
 * against. Without it these four checks prove the bundle is internally
 * consistent and is about these exact bytes — not that the identity in it is
 * real. Those gaps are listed in {@link ProvenanceFact.notChecked} and printed
 * in the report, so no reader has to infer them.
 * @module dsh-plugin-inspector/attestation
 */

import { X509Certificate, createHash, createVerify } from 'node:crypto'

/** The SLSA predicate type npm publishes a build provenance statement under. */
export const PROVENANCE_PREDICATE_TYPE = 'https://slsa.dev/provenance/v1'

/**
 * Largest attestation document the tool will read. Real bundles are tens of
 * kilobytes; the transparency-log inclusion proof is most of that.
 */
export const MAX_ATTESTATION_BYTES = 1024 * 1024

/**
 * How much provenance this report has.
 *
 * `absent` is the common case and is not a defect: most published packages
 * carry no attestation. `unavailable` is the honest answer for a directory or
 * a local tarball, neither of which has a registry statement to read.
 */
export type ProvenanceState = 'unavailable' | 'absent' | 'unreadable' | 'attested' | 'failed'

/** The name of one check this tool runs against a fetched attestation. */
export type ProvenanceCheckName =
  | 'subject-digest'
  | 'subject-package'
  | 'dsse-signature'
  | 'certificate-identity'

/**
 * Something a full verifier would establish and this tool does not.
 *
 * `certificate-chain` and `transparency-log` are unconditional: both need the
 * Sigstore trust root. `builder-identity` appears when the statement does not
 * name a GitHub Actions workflow, which is the only build type whose signer
 * identity this tool knows how to reconstruct from the payload.
 */
export type ProvenanceGap = 'certificate-chain' | 'transparency-log' | 'builder-identity'

/** Gaps that hold for every attestation, whatever is in it. */
const UNCONDITIONAL_GAPS: readonly ProvenanceGap[] = ['certificate-chain', 'transparency-log']

/** The outcome of one check, with what it compared. */
export interface ProvenanceCheck {
  readonly name: ProvenanceCheckName
  /** What was compared against what, in one line. */
  readonly detail: string
  readonly passed: boolean
}

/** Everything a fact says about the build, whatever state it is in. */
interface ProvenanceClaims {
  /** The predicate type the statement carries. */
  readonly predicateType: string | null
  /** The source repository the statement names, e.g. `https://github.com/owner/repo`. */
  readonly sourceRepository: string | null
  /** The commit that repository was built from. */
  readonly sourceCommit: string | null
  /** The git ref the build ran on, e.g. `refs/tags/v1.2.3`. */
  readonly sourceRef: string | null
  /** Repository-relative path of the workflow that built it. */
  readonly workflow: string | null
  /** The builder the statement names, e.g. a GitHub-hosted runner. */
  readonly builder: string | null
  /** The identity in the signing certificate's subject alternative name. */
  readonly signerIdentity: string | null
  /** Every check that ran, in a fixed order. */
  readonly checks: readonly ProvenanceCheck[]
  /** Every claim this tool did not establish. */
  readonly notChecked: readonly ProvenanceGap[]
}

/**
 * What the registry says about this package's build origin, and what of it was
 * checked. Emitted for every report, including the two modes that have no
 * registry statement to read at all.
 *
 * The state carries the two fields whose presence depends on it, so a consumer
 * never has to ask whether a `reason` is meaningful in the state it found: the
 * two states that have a reason always have one, and the two that report on a
 * real attestation always name the endpoint it came from.
 */
export type ProvenanceFact =
  | (ProvenanceClaims & {
    readonly state: 'unavailable'
    /** Why this mode has no attestation to read. */
    readonly reason: string
    readonly attestationUrl: null
  })
  | (ProvenanceClaims & {
    readonly state: 'absent'
    readonly reason: null
    readonly attestationUrl: null
  })
  | (ProvenanceClaims & {
    readonly state: 'unreadable'
    /** What went wrong reading the attestation the registry said it holds. */
    readonly reason: string
    /** The endpoint that was asked, or `null` when none could be built. */
    readonly attestationUrl: string | null
  })
  | (ProvenanceClaims & {
    readonly state: 'attested' | 'failed'
    readonly reason: null
    /** The registry endpoint the bundle was read from. */
    readonly attestationUrl: string
  })

/** What a fetched attestation is checked against. */
export interface ProvenanceSubject {
  readonly name: string
  readonly version: string
  /** The tarball bytes, already checked against `dist.integrity`. */
  readonly tarball: Buffer
  /** The endpoint the document came from, recorded in the fact. */
  readonly url: string
}

/** A fact carrying no attestation, with every claim spelled out as absent. */
const NOTHING = {
  predicateType: null,
  sourceRepository: null,
  sourceCommit: null,
  sourceRef: null,
  workflow: null,
  builder: null,
  signerIdentity: null,
  checks: [],
  notChecked: [],
} as const

/**
 * The fact for a target that has no registry statement: a directory, or a
 * tarball on disk. Stated rather than reported as an absence, because "this
 * package has no provenance" and "this mode cannot read provenance" are
 * different answers and only one of them is about the package.
 * @returns the fact.
 */
export function provenanceUnavailable(): ProvenanceFact {
  return {
    ...NOTHING,
    state: 'unavailable',
    reason: 'a directory or local tarball carries no registry attestation; --from-npm reads one',
    attestationUrl: null,
  }
}

/**
 * The fact for a published package whose version document declares no
 * provenance attestation.
 * @returns the fact.
 */
export function provenanceAbsent(): ProvenanceFact {
  return { ...NOTHING, state: 'absent', reason: null, attestationUrl: null }
}

/**
 * The fact for an attestation the registry named but this run could not read.
 * @param url - the endpoint that was asked, or `null` when none could be built.
 * @param reason - what went wrong.
 * @returns the fact.
 */
export function provenanceUnreadable(url: string | null, reason: string): ProvenanceFact {
  return { ...NOTHING, state: 'unreadable', reason, attestationUrl: url }
}

/**
 * Narrow an unknown JSON value to a record, so a hostile document's
 * `attestations: 7` reads as "no fields" rather than throwing further down.
 * @param value - the parsed JSON value.
 * @returns the value as a record, or an empty one.
 */
function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

/**
 * Read a string field, or `null` when it is absent or of another type.
 * @param record - the containing record.
 * @param key - the field name.
 * @returns the string, or `null`.
 */
function asString(record: Record<string, unknown>, key: string): string | null {
  const value = record[key]
  return typeof value === 'string' ? value : null
}

/**
 * The package URL npm writes an attestation subject's name as. A scope's `@`
 * is percent-encoded there and nowhere else in the document.
 * @param name - the package name.
 * @param version - the resolved version.
 * @returns the package URL.
 */
export function packageUrl(name: string, version: string): string {
  return `pkg:npm/${name.replace(/^@/, '%40')}@${version}`
}

/**
 * The pre-authentication encoding DSSE signs: the payload type and the payload,
 * each preceded by its length, so neither can be shifted into the other.
 * @param payloadType - the envelope's declared payload type.
 * @param payload - the decoded payload.
 * @returns the bytes the signature covers.
 */
function preAuthenticationEncoding(payloadType: string, payload: Buffer): Buffer {
  const type = Buffer.from(payloadType, 'utf8')
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'utf8'),
    type,
    Buffer.from(` ${payload.length} `, 'utf8'),
    payload,
  ])
}

/**
 * The signing certificate a Sigstore bundle carries. Bundle media type 0.2
 * carries a chain and 0.3 carries the leaf alone; npm publishes both, so both
 * are read.
 * @param material - the bundle's `verificationMaterial`.
 * @returns the leaf certificate's DER bytes, or `null`.
 */
function leafCertificate(material: Record<string, unknown>): Buffer | null {
  const single = asString(asRecord(material.certificate), 'rawBytes')
  if (single !== null) return Buffer.from(single, 'base64')
  const chain = asRecord(material.x509CertificateChain).certificates
  if (!Array.isArray(chain)) return null
  const first = asString(asRecord(chain[0]), 'rawBytes')
  return first === null ? null : Buffer.from(first, 'base64')
}

/** The parts of a bundle the checks read, once it has been decoded. */
interface DecodedBundle {
  readonly certificate: X509Certificate
  readonly payload: Buffer
  readonly payloadType: string
  readonly signature: Buffer
  readonly statement: Record<string, unknown>
}

/** Raised for an attestation document this tool cannot read at all. */
class UnreadableAttestation extends Error {}

/**
 * Pull the provenance bundle out of a registry attestation document.
 * @param body - the document as served.
 * @returns the parts the checks read.
 * @throws UnreadableAttestation when the document holds no readable provenance bundle.
 */
function decode(body: Buffer): DecodedBundle {
  let document: unknown
  try {
    document = JSON.parse(body.toString('utf8'))
  } catch (error) {
    /* v8 ignore next -- JSON.parse rejects text only with a SyntaxError. */
    const detail = error instanceof Error ? error.message : String(error)
    throw new UnreadableAttestation(`the attestation endpoint did not return JSON: ${detail}`)
  }
  const list = asRecord(document).attestations
  const entries = Array.isArray(list) ? list.map(asRecord) : []
  const entry = entries.find(candidate => asString(candidate, 'predicateType') === PROVENANCE_PREDICATE_TYPE)
  if (entry === undefined) {
    throw new UnreadableAttestation(`the document carries no ${PROVENANCE_PREDICATE_TYPE} attestation`)
  }
  const bundle = asRecord(entry.bundle)
  const der = leafCertificate(asRecord(bundle.verificationMaterial))
  if (der === null) throw new UnreadableAttestation('the bundle carries no signing certificate')
  let certificate: X509Certificate
  try {
    certificate = new X509Certificate(der)
  } catch (error) {
    /* v8 ignore next -- X509Certificate rejects bytes only with an Error. */
    const detail = error instanceof Error ? error.message : String(error)
    throw new UnreadableAttestation(`the bundle's signing certificate does not parse: ${detail}`)
  }
  const envelope = asRecord(bundle.dsseEnvelope)
  const encoded = asString(envelope, 'payload')
  const payloadType = asString(envelope, 'payloadType')
  const signatures = envelope.signatures
  const signature = Array.isArray(signatures) ? asString(asRecord(signatures[0]), 'sig') : null
  if (encoded === null || payloadType === null || signature === null) {
    throw new UnreadableAttestation('the bundle carries no complete DSSE envelope')
  }
  const payload = Buffer.from(encoded, 'base64')
  let statement: unknown
  try {
    statement = JSON.parse(payload.toString('utf8'))
  } catch (error) {
    /* v8 ignore next -- JSON.parse rejects text only with a SyntaxError. */
    const detail = error instanceof Error ? error.message : String(error)
    throw new UnreadableAttestation(`the signed statement is not JSON: ${detail}`)
  }
  return {
    certificate,
    payload,
    payloadType,
    signature: Buffer.from(signature, 'base64'),
    statement: asRecord(statement),
  }
}

/** What a GitHub Actions provenance statement says about the build. */
interface BuildClaims {
  readonly repository: string | null
  readonly commit: string | null
  readonly ref: string | null
  readonly workflow: string | null
  readonly builder: string | null
}

/**
 * Read the build claims out of a SLSA v1 predicate.
 * @param statement - the decoded in-toto statement.
 * @returns what it says about the source and the builder.
 */
function readClaims(statement: Record<string, unknown>): BuildClaims {
  const predicate = asRecord(statement.predicate)
  const definition = asRecord(predicate.buildDefinition)
  const workflow = asRecord(asRecord(definition.externalParameters).workflow)
  const dependencies = definition.resolvedDependencies
  const source = asRecord(Array.isArray(dependencies) ? dependencies[0] : undefined)
  return {
    repository: asString(workflow, 'repository'),
    commit: asString(asRecord(source.digest), 'gitCommit'),
    ref: asString(workflow, 'ref'),
    workflow: asString(workflow, 'path'),
    builder: asString(asRecord(asRecord(predicate.runDetails).builder), 'id'),
  }
}

/**
 * Every subject the statement names, as name and SHA-512 pairs.
 * @param statement - the decoded in-toto statement.
 * @returns one entry per subject the document could be read for.
 */
function readSubjects(statement: Record<string, unknown>): { name: string | null, sha512: string | null }[] {
  const subjects = statement.subject
  if (!Array.isArray(subjects)) return []
  return subjects.map(asRecord).map(subject => ({
    name: asString(subject, 'name'),
    sha512: asString(asRecord(subject.digest), 'sha512'),
  }))
}

/**
 * Verify the DSSE signature under the public key of the certificate in the
 * bundle.
 *
 * A failure here is a bundle whose payload and signature disagree. A success
 * says only that; it says nothing about who holds the key, which is the gap
 * `certificate-chain` names.
 * @param bundle - the decoded bundle.
 * @returns the check result.
 */
function checkSignature(bundle: DecodedBundle): ProvenanceCheck {
  const signed = preAuthenticationEncoding(bundle.payloadType, bundle.payload)
  let passed: boolean
  try {
    const verifier = createVerify('sha256')
    verifier.update(signed)
    verifier.end()
    passed = verifier.verify(bundle.certificate.publicKey, bundle.signature)
  } catch (error) {
    /* v8 ignore next -- `verify` refuses a key it cannot use only with an Error. */
    const detail = error instanceof Error ? error.message : String(error)
    return {
      name: 'dsse-signature',
      detail: `the signature could not be checked against the bundle's certificate: ${detail}`,
      passed: false,
    }
  }
  return {
    name: 'dsse-signature',
    detail: passed
      ? 'the DSSE signature verifies under the public key of the certificate in the bundle'
      : 'the DSSE signature does not verify under the public key of the certificate in the bundle',
    passed,
  }
}

/**
 * Compare the certificate's subject alternative name against the workflow the
 * statement claims. Fulcio writes the workflow identity there as
 * `<repository>/<path>@<ref>`, so the two are the same claim from two places in
 * the bundle and a mismatch means one of them was swapped.
 * @param bundle - the decoded bundle.
 * @param claims - what the statement says about the build.
 * @returns the check, or `null` when the statement names no workflow to compare.
 */
function checkIdentity(bundle: DecodedBundle, claims: BuildClaims): ProvenanceCheck | null {
  if (claims.repository === null || claims.workflow === null || claims.ref === null) return null
  const expected = `${claims.repository}/${claims.workflow}@${claims.ref}`
  const names = (bundle.certificate.subjectAltName ?? '').split(', ')
  const passed = names.includes(`URI:${expected}`)
  return {
    name: 'certificate-identity',
    detail: passed
      ? `the signing certificate names ${expected}, which is the workflow the statement claims`
      : `the statement claims ${expected} but the signing certificate names `
        + `${bundle.certificate.subjectAltName ?? 'nothing'}`,
    passed,
  }
}

/**
 * Check a fetched attestation document against the tarball this run analysed.
 *
 * The digest comparison is the load-bearing one: it is what ties the statement
 * to these bytes rather than to some other version of the same package. The
 * bytes handed in are the ones `dist.integrity` already vouched for, so a pass
 * here means one chain of digests runs from the version document through the
 * download to the signed statement.
 * @param body - the attestation document as served.
 * @param subject - the package the document is supposed to be about.
 * @returns the fact, in state `attested`, `failed`, or `unreadable`.
 */
export function readProvenance(body: Buffer, subject: ProvenanceSubject): ProvenanceFact {
  let bundle: DecodedBundle
  try {
    bundle = decode(body)
  } catch (error) {
    /* v8 ignore next -- `decode` reports every refusal as an UnreadableAttestation. */
    if (!(error instanceof UnreadableAttestation)) throw error
    return provenanceUnreadable(subject.url, error.message)
  }
  const claims = readClaims(bundle.statement)
  const subjects = readSubjects(bundle.statement)
  const digest = createHash('sha512').update(subject.tarball).digest('hex')
  const expectedName = packageUrl(subject.name, subject.version)
  const digestMatched = subjects.some(entry => entry.sha512 === digest)
  const nameMatched = subjects.some(entry => entry.name === expectedName)
  const identity = checkIdentity(bundle, claims)
  const checks: ProvenanceCheck[] = [
    {
      name: 'subject-digest',
      detail: digestMatched
        ? 'the statement covers the exact bytes this run analysed, by SHA-512'
        : `the statement covers no artifact with the SHA-512 of the downloaded tarball (${digest})`,
      passed: digestMatched,
    },
    {
      name: 'subject-package',
      detail: nameMatched
        ? `the statement is about ${expectedName}`
        : `the statement names ${subjects.map(entry => entry.name ?? '(unnamed)').join(', ') || 'no subject'}`
          + `, not ${expectedName}`,
      passed: nameMatched,
    },
    checkSignature(bundle),
    ...identity === null ? [] : [identity],
  ]
  return {
    state: checks.every(check => check.passed) ? 'attested' : 'failed',
    reason: null,
    predicateType: PROVENANCE_PREDICATE_TYPE,
    sourceRepository: claims.repository,
    sourceCommit: claims.commit,
    sourceRef: claims.ref,
    workflow: claims.workflow,
    builder: claims.builder,
    signerIdentity: bundle.certificate.subjectAltName ?? null,
    attestationUrl: subject.url,
    checks,
    notChecked: identity === null ? [...UNCONDITIONAL_GAPS, 'builder-identity'] : UNCONDITIONAL_GAPS,
  }
}
