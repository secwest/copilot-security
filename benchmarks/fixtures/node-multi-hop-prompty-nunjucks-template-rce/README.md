# Vulnerable Prompty Nunjucks template fixture

An Express query parameter crosses three relative-import wrappers into the
official `@prompty/core` Nunjucks renderer under exact affected
`2.0.0-beta.4` runtime provenance. `witness.mjs` uses a bounded, non-shell
template that traverses the built-in `range` function's constructor and
returns only the local Node version.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
