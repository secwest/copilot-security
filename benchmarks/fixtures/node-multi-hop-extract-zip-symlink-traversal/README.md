# Vulnerable extract-zip symlink-target traversal

An Express upload path crosses three relative-import wrappers into `extract-zip` 2.0.1. The entry callback observes a Unix symlink but does not reject it, so a contained archive member can materialize a link whose payload points outside the extraction root. A later application read through that link discloses protected configuration.

`witness.mjs` reproduces the boundary failure without installing or executing the vulnerable package.
