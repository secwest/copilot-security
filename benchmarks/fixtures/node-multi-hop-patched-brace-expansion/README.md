# Patched brace-expansion intermediate-array boundary

This source-identical control upgrades only `brace-expansion` from 5.0.8 to
5.0.9. The repaired release applies both result-count and character-work bounds
while constructing padded sequences and comma alternatives, rather than after
the intermediate arrays already exist.

Run `npm install --ignore-scripts && npm test` to confirm that the same output
is produced without the vulnerable intermediate work.
