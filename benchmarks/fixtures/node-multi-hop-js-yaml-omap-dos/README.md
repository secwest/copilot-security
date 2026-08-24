# Vulnerable js-yaml ordered-map parsing

An HTTP request body crosses three relative-import wrappers before `js-yaml` 4.3.0 parses it. The default schema's `!!omap` resolver linearly scans every previously seen key for each unique entry, producing quadratic synchronous CPU work and blocking the Node.js event loop.

The dependency-free witness counts the affected duplicate-key comparisons and proves quadratic growth without installing or executing vulnerable package code.
