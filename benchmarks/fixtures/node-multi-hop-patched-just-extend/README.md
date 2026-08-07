# Multi-hop patched just-extend merge

This control preserves the Express source, three relative-import wrappers, and exact `extend(true, target, ...sources)` call. Its nearest runtime manifest pins `just-extend` 4.0.1, whose own-property destination check prevents the 4.0.0 traversal into global `Object.prototype`. The route measures that cross-object boundary through a fresh policy object rather than treating target-local prototype replacement as equivalent global pollution.

The dependency-free witness reproduces the upstream fixed lookup. The fixture never installs the package; scanner acceptance requires the matching package identity and version proof before excluding this historical model.
