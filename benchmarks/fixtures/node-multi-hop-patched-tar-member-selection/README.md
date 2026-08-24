# Patched node-tar member-selection recursion

This source-identical control upgrades only `tar` to 7.5.21. That release caps the internal `filesFilter/mapHas` parent walk at 100 levels before a long GNU or PAX path can exhaust the JavaScript stack.

`witness.mjs` exercises the bounded algorithm over the same 12,000-segment shape without installing the package.
