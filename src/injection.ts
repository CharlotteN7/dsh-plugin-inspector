/**
 * Prompt-injection heuristics, applied to model-visible text only.
 *
 * "Model-visible" is a narrow set on purpose: shipped skill and
 * agent-instruction markdown, and the `description` string of a registered
 * tool. Those reach the model verbatim, unescaped and uncapped. Ordinary source
 * comments do not, and scanning them would produce a stream of false positives
 * from documentation that happens to quote an attack.
 *
 * These are heuristics over natural language. They will miss a rephrased
 * instruction and they will occasionally fire on a legitimate document that
 * discusses prompt injection. Both directions are stated in the finding.
 * @module dsh-plugin-inspector/injection
 */

/** One heuristic and what it is looking for. */
export interface InjectionRule {
  readonly id: string
  readonly pattern: RegExp
  /** What a match would mean, phrased for a report. */
  readonly meaning: string
}

/**
 * The rule table. Each pattern targets an instruction that only makes sense if
 * the author expects a model rather than a person to read it.
 */
export const INJECTION_RULES: readonly InjectionRule[] = [
  {
    id: 'override-prior-instructions',
    pattern: /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(?:instruction|prompt|rule|direction|guideline)/i,
    meaning: 'tells the model to discard instructions it was already given',
  },
  {
    id: 'role-reassignment',
    pattern: /\b(?:you are now|from now on,? you (?:are|will|must|should)|your new (?:role|task|instruction))\b/i,
    meaning: 'reassigns the model\'s role',
  },
  {
    id: 'conceal-from-user',
    pattern: /\b(?:do not|don't|never)\b[^.\n]{0,30}\b(?:tell|inform|mention|reveal|show|display|report)\b[^.\n]{0,20}\buser\b/i,
    meaning: 'instructs the model to hide something from the user',
  },
  {
    id: 'bypass-approval',
    pattern: /\bwithout\b[^.\n]{0,30}\b(?:asking|confirming|approval|permission|prompting)\b/i,
    meaning: 'instructs the model to act without the approval step',
  },
  {
    id: 'credential-exfiltration',
    // The dotted filenames carry their own boundary. A `\b` in front of the
    // whole alternation cannot match at the start of `.env` or `.npmrc`: the
    // preceding character is a space and the next is a `.`, so neither side of
    // that position is a word character and the boundary does not exist there.
    // Under a shared `\b` those two alternatives match nothing, while the
    // word-initial ones beside them keep working and hide it.
    pattern: /\b(?:send|post|upload|transmit|exfiltrate|forward|report)\b[^.\n]{0,60}(?:\b(?:api[_ -]?key|access[_ -]?token|secret|credential|password|id_rsa)\b|\.(?:env|npmrc)\b)/i,
    meaning: 'instructs the model to move a credential somewhere',
  },
  {
    id: 'system-prompt-disclosure',
    pattern: /\b(?:reveal|print|output|repeat|show|dump)\b[^.\n]{0,30}\b(?:system prompt|initial instructions|your instructions)\b/i,
    meaning: 'asks the model to disclose its system prompt',
  },
  {
    id: 'pipe-to-shell',
    pattern: /\b(?:curl|wget)\b[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/i,
    meaning: 'contains a download-and-execute shell pipeline',
  },
  {
    id: 'encoded-payload',
    pattern: /\b(?:base64\s+(?:-d|--decode)|atob\s*\(|echo\s+[A-Za-z0-9+/]{40,}={0,2}\s*\|)/,
    meaning: 'contains an encoded payload the reader cannot evaluate',
  },
  {
    id: 'hidden-characters',
    pattern: /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]|[\u{E0000}-\u{E007F}]/u,
    meaning: 'contains zero-width or bidirectional-control characters, which change what a human reader sees but not what the model reads',
  },
  {
    // Keyed on a run of four, not on a single selector. One selector is
    // ordinary: U+FE0F and U+FE0E pick the emoji or text presentation of the
    // character before them, and the U+E01xx plane carries the Ideographic
    // Variation Sequences that CJK text uses, so firing on one would fire on
    // every document with an emoji in it. Nothing standardised puts four in a
    // row: a variation selector modifies the single character it follows, so a
    // second one has nothing to modify. GlassWorm's five waves encoded
    // executable JavaScript one byte per selector, which makes any real payload
    // an unbroken run of tens to thousands. Four is far below that and above
    // the doubled selectors that copy-paste through an editor produces.
    id: 'variation-selector-payload',
    pattern: /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]{4,}/u,
    meaning: 'contains a run of variation selectors, which occupy no width in any editor, terminal or diff '
      + 'view and can carry an arbitrary encoded payload one byte per selector',
  },
  {
    id: 'hidden-html-instruction',
    pattern: /<!--[^]{0,400}?\b(?:you (?:must|should|are)|instruction|assistant|ignore)\b[^]{0,400}?-->/i,
    meaning: 'hides an instruction inside an HTML comment, invisible in rendered markdown',
  },
]

/** One heuristic match. */
export interface InjectionMatch {
  readonly ruleId: string
  readonly meaning: string
  /** Character offset of the match in the scanned text. */
  readonly index: number
  readonly excerpt: string
}

/**
 * Scan model-visible text for injection phrasing.
 * @param text - the text a model would receive.
 * @returns one match per rule that fired, at its first occurrence.
 */
export function scanInjection(text: string): InjectionMatch[] {
  const matches: InjectionMatch[] = []
  for (const rule of INJECTION_RULES) {
    const found = rule.pattern.exec(text)
    if (found === null) continue
    matches.push({
      ruleId: rule.id,
      meaning: rule.meaning,
      index: found.index,
      excerpt: text.slice(Math.max(0, found.index - 20), found.index + found[0].length + 20),
    })
  }
  return matches
}
