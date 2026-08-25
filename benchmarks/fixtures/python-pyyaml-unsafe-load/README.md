# Python PyYAML unsafe-load benchmark

The Flask route sends the exact request body through one relative Python wrapper
to `yaml.load(..., Loader=yaml.UnsafeLoader)`. PyYAML may construct
Python-specific objects while loading the document, before application-level
validation can inspect the result.

The paired control has the same files, route, wrapper, and request flow. It
changes only the parser boundary to `yaml.safe_load`, which limits construction
to the safe YAML tag set.

`python3 examples/witness.py` uses the harmless PyYAML-specific
`!!python/tuple` tag. This fixture constructs a real Python tuple; the paired
control rejects the same input. The witness opens no listener, performs no
network request, invokes no shell, and writes no file.
