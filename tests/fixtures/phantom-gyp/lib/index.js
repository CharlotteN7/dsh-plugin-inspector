/**
 * The whole of this package's declared behavior: a plugin that registers
 * nothing. A reader who checks `main`, `bin`, `exports` and `scripts` sees this
 * file and stops, which is the reason the build declaration is worth reporting.
 */
export function apply() {}
