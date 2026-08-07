# Patched object-path inherited deletion flow

The source, three wrappers, receiver mode, target, and official `del` call are
identical to the vulnerable fixture, but object-path 0.11.8 rejects magic
property access before inherited deletion can reach `Object.prototype`.
