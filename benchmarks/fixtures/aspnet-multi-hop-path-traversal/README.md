# ASP.NET multi-hop path-traversal fixture

The `path` query parameter crosses two uniquely typed, constructor-injected
service boundaries before it becomes the second argument of `Path.Combine` and
then the path passed to `File.ReadAllTextAsync`. A rooted value discards the
configured content root, while a relative `..` sequence escapes it. The fixture
contains no attacker-writable content-root assumption or link behavior that
could confound the lexical path-boundary defect.
