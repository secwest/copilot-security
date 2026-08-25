# Runtime validation contract

The bounded witness is regression-tested with the same `numpy==2.5.2`
dependency on both supported acceptance environments:

- Python 3.12.3 and NumPy 2.5.2 on Linux
- Python 3.14.5 and NumPy 2.5.2 on Windows

`examples/witness.py` reports the interpreter and NumPy versions it actually
executes. This matrix is evidence for the fixture's executable behavior; it is
not evidence that an unrelated deployed service uses either Python version.
