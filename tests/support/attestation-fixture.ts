/**
 * Building a Sigstore-shaped attestation bundle a test can control every field
 * of.
 *
 * A real npm bundle can only ever produce one scenario — the passing one — and
 * mutating its payload breaks the signature, so "a valid signature over a
 * statement about the wrong artifact" cannot be built from a captured document
 * at all. That case is the one the digest check exists for, so the fixture has
 * to sign its own statements, which means issuing its own certificate.
 *
 * The certificate is self-signed, and that is the point rather than a
 * shortcut: `attestation.ts` does not chain the certificate to a trust root and
 * says so, so a self-signed certificate passing every check it does run is the
 * documented limit demonstrated rather than described.
 * @module tests/support/attestation-fixture
 */

import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto'

/** DER tag numbers this module writes. */
const TAG = {
  boolean: 0x01,
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  oid: 0x06,
  utf8String: 0x0c,
  sequence: 0x30,
  set: 0x31,
  utcTime: 0x17,
  /** GeneralName `uniformResourceIdentifier`, context tag 6, primitive. */
  uri: 0x86,
  /** `[0]` explicit, holding the certificate version. */
  version: 0xa0,
  /** `[3]` explicit, holding the extensions. */
  extensions: 0xa3,
} as const

/**
 * DER length octets: short form under 128, long form above.
 * @param length - the content length.
 * @returns the encoded length.
 */
function length(length_: number): Buffer {
  if (length_ < 0x80) return Buffer.from([length_])
  const bytes: number[] = []
  for (let rest = length_; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest % 256)
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

/**
 * One DER element.
 * @param tag - the tag octet.
 * @param content - the content octets.
 * @returns the encoded element.
 */
function element(tag: number, ...content: Buffer[]): Buffer {
  const body = Buffer.concat(content)
  return Buffer.concat([Buffer.from([tag]), length(body.length), body])
}

/** `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2. */
const ECDSA_SHA256 = Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])

/** `id-ce-subjectAltName`, 2.5.29.17. */
const SUBJECT_ALT_NAME = Buffer.from([0x55, 0x1d, 0x11])

/** `id-at-commonName`, 2.5.4.3. */
const COMMON_NAME = Buffer.from([0x55, 0x04, 0x03])

/**
 * A distinguished name holding one common name.
 * @param common - the common name.
 * @returns the encoded Name.
 */
function name(common: string): Buffer {
  return element(TAG.sequence, element(TAG.set, element(
    TAG.sequence,
    element(TAG.oid, COMMON_NAME),
    element(TAG.utf8String, Buffer.from(common, 'utf8')),
  )))
}

/**
 * A UTCTime, which is what a certificate uses for years before 2050.
 * @param when - the moment.
 * @returns the encoded time.
 */
function utcTime(when: Date): Buffer {
  const text = when.toISOString().replace(/[-:T]/g, '').replace(/\.\d+Z$/, 'Z').slice(2)
  return element(TAG.utcTime, Buffer.from(text, 'utf8'))
}

/** An issued certificate and the key that can sign under it. */
export interface SigningIdentity {
  /** The certificate in DER, as a bundle carries it. */
  readonly certificate: Buffer
  readonly privateKey: KeyObject
}

/**
 * Issue a self-signed P-256 certificate whose only extension is a critical
 * subject alternative name, which is where Fulcio writes the workflow identity.
 * @param identity - the URI to put in the subject alternative name, or `null`
 * for a certificate carrying no subject alternative name at all.
 * @param keyType - the key to issue over. `ed25519` produces a certificate no
 * Fulcio would issue, which is how a test reaches the branch where the DSSE
 * signature cannot be checked at all rather than merely failing.
 * @returns the certificate and its private key.
 */
export function issueCertificate(identity: string | null, keyType: 'ec' | 'ed25519' = 'ec'): SigningIdentity {
  const { publicKey, privateKey } = keyType === 'ed25519'
    ? generateKeyPairSync('ed25519')
    : generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const algorithm = element(TAG.sequence, element(TAG.oid, ECDSA_SHA256))
  const tbs = element(
    TAG.sequence,
    element(TAG.version, element(TAG.integer, Buffer.from([0x02]))),
    element(TAG.integer, Buffer.from([0x01])),
    algorithm,
    name('attestation-fixture-intermediate.test'),
    element(TAG.sequence, utcTime(new Date('2026-01-01T00:00:00Z')), utcTime(new Date('2026-01-01T00:10:00Z'))),
    element(TAG.sequence),
    publicKey.export({ type: 'spki', format: 'der' }),
    ...identity === null ? [] : [element(TAG.extensions, element(TAG.sequence, element(
      TAG.sequence,
      element(TAG.oid, SUBJECT_ALT_NAME),
      element(TAG.boolean, Buffer.from([0xff])),
      element(TAG.octetString, element(TAG.sequence, element(TAG.uri, Buffer.from(identity, 'utf8')))),
    )))],
  )
  const certificate = element(
    TAG.sequence,
    tbs,
    algorithm,
    element(TAG.bitString, Buffer.from([0x00]), sign(keyType === 'ed25519' ? null : 'sha256', tbs, privateKey)),
  )
  return { certificate, privateKey }
}

/**
 * The pre-authentication encoding DSSE signs.
 * @param payloadType - the envelope's payload type.
 * @param payload - the payload bytes.
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

/** What a fabricated provenance statement should say. */
export interface StatementOptions {
  /** Package name, written into the subject as a package URL. */
  readonly name: string
  readonly version: string
  /** The artifact the statement covers; its SHA-512 becomes the subject digest. */
  readonly tarball: Buffer
  readonly repository: string
  readonly commit: string
  readonly ref: string
  readonly workflow: string
}

/**
 * A SLSA v1 provenance statement in the shape npm publishes.
 * @param options - what it should say.
 * @returns the statement.
 */
export function statement(options: StatementOptions): Record<string, unknown> {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{
      name: `pkg:npm/${options.name.replace(/^@/, '%40')}@${options.version}`,
      digest: { sha512: createHash('sha512').update(options.tarball).digest('hex') },
    }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: {
          workflow: { ref: options.ref, repository: options.repository, path: options.workflow },
        },
        resolvedDependencies: [{
          uri: `git+${options.repository}@${options.ref}`,
          digest: { gitCommit: options.commit },
        }],
      },
      runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } },
    },
  }
}

/** How the fixture should be assembled, beyond the statement itself. */
export interface BundleOptions {
  /**
   * The identity to sign under; defaults to the workflow the statement claims.
   * `null` issues a certificate with no subject alternative name.
   */
  readonly identity?: string | null
  /** Signed instead of the statement, so the envelope's signature does not match it. */
  readonly signInstead?: Record<string, unknown>
  /** Bundle media type; the 0.2 form carries a chain, the 0.3 form a bare leaf. */
  readonly mediaType?: 'v0.2' | 'v0.3'
  /** The statement to put in the envelope, replacing the one `claims` describes. */
  readonly payload?: Record<string, unknown>
  /** The signing key type; `ed25519` is one no signature check can run against. */
  readonly keyType?: 'ec' | 'ed25519'
}

/**
 * A registry attestation document holding one signed provenance bundle.
 * @param claims - what the statement should say.
 * @param options - how to assemble the bundle.
 * @returns the document, ready to serve.
 */
export function attestationDocument(
  claims: StatementOptions, options: BundleOptions = {},
): Record<string, unknown> {
  const identity = options.identity === undefined
    ? `${claims.repository}/${claims.workflow}@${claims.ref}`
    : options.identity
  const { certificate, privateKey } = issueCertificate(identity, options.keyType ?? 'ec')
  const payload = Buffer.from(JSON.stringify(options.payload ?? statement(claims)), 'utf8')
  const signed = options.signInstead === undefined
    ? payload
    : Buffer.from(JSON.stringify(options.signInstead), 'utf8')
  const payloadType = 'application/vnd.in-toto+json'
  const signature = sign(
    options.keyType === 'ed25519' ? null : 'sha256',
    preAuthenticationEncoding(payloadType, signed),
    privateKey,
  )
  const rawBytes = certificate.toString('base64')
  const material = options.mediaType === 'v0.2'
    ? { x509CertificateChain: { certificates: [{ rawBytes }] } }
    : { certificate: { rawBytes } }
  return {
    attestations: [
      {
        predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
        bundle: { mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2' },
      },
      {
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: {
          mediaType: options.mediaType === 'v0.2'
            ? 'application/vnd.dev.sigstore.bundle+json;version=0.2'
            : 'application/vnd.dev.sigstore.bundle.v0.3+json',
          verificationMaterial: { ...material, tlogEntries: [] },
          dsseEnvelope: {
            payload: payload.toString('base64'),
            payloadType,
            signatures: [{ sig: signature.toString('base64'), keyid: '' }],
          },
        },
      },
    ],
  }
}
