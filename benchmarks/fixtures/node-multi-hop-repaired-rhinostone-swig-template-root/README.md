# Repaired Rhinostone Swig loader-root control

This source-identical control changes only `@rhinostone/swig` from 2.7.0 to
2.7.2. The rooted filesystem loader rejects the same dynamic `include` target
before it can read the fixture's adjacent `src/secret.txt` file.

The witness opens no listener, invokes no shell, and changes no persistent
state.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
