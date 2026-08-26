# Vulnerable Rhinostone Swig template-path fixture

An Express query value crosses three relative-module calls into the `partial`
local of a trusted Swig template. The template uses that local as a dynamic
`include` target under the exact vulnerable `@rhinostone/swig` 2.7.0 runtime
and an explicitly rooted filesystem loader.

The bounded witness selects only the fixture's adjacent `src/secret.txt` file.
It opens no listener, invokes no shell, and changes no persistent state.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
