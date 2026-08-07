# Vulnerable PostCSS previous-map traversal

An Express CSS body crosses three relative-import wrappers into PostCSS 8.5.17. A final `sourceMappingURL=../protected.map` annotation causes the default previous-map loader to read outside the `from` directory, and the route returns the generated map with its protected `sourcesContent`.

`witness.mjs` reproduces the containment failure without installing the vulnerable package and removes its private temporary root afterward.
