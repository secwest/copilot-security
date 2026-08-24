# Repaired vm2 sandbox control

This source-identical control changes only the vm2 runtime to 3.11.6. The same
bounded host-version witness is stopped by the repaired bridge before it can
recover the host process.
The repaired package also denies `os` to the source-identical wildcard
`NodeVM` host-identity check.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
