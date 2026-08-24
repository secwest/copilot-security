# Patched js-yaml flow-pair parsing

This source-identical control upgrades only `js-yaml` to 5.2.2. The repaired parser inserts an event around the already parsed flow-pair key instead of rewinding and parsing the nested key again.

The dependency-free witness uses the same depth and payload shape while proving that the repaired event path performs linear work.
