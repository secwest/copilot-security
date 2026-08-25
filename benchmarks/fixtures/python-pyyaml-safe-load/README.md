# Python PyYAML safe-load control

This source-topology-identical control keeps the Flask request body and relative
parser wrapper, but uses `yaml.safe_load`. The safe loader does not construct
arbitrary Python objects.

`python3 examples/witness.py` supplies the same harmless `!!python/tuple` tag
as the vulnerable fixture and records its fail-closed constructor rejection.
