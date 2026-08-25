# NumPy object-array deserialization benchmark

This fixture accepts an uploaded `.npy` file and passes its seekable stream
through a relative wrapper to `numpy.load(..., allow_pickle=True)`. The witness
creates an object-dtype array whose bounded `__reduce__` callable records a
harmless in-process effect during loading.

The route caps the complete request, and the parser independently caps bytes,
header size, rank, and element count before the final load. Those controls keep
the pair focused on the explicit pickle boundary rather than generic upload or
array-allocation exhaustion.

Run `python examples/witness.py` after installing `requirements.txt`.
See `RUNTIME.md` for the exact cross-platform witness matrix and the boundary
between fixture validation evidence and a deployed service's runtime.
