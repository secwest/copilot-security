# Patched tmp path-boundary control

This fixture preserves the Express source, three relative-import boundaries,
creator API, option position, and protected export write from the vulnerable
fixture while pinning `tmp` 0.2.6. The repaired package rejects the relative
prefix before creating a filesystem object.
