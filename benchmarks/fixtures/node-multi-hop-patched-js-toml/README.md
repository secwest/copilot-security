# Patched js-toml parser control

This matched control preserves the Express source, three wrapper boundaries,
and official `load` call while pinning js-toml 1.0.2. That release constructs
the root and nested parser objects with null prototypes, so hostile table names
remain data instead of reaching `Object.prototype`.
