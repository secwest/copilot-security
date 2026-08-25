# NumPy object-array deserialization benchmark

This fixture accepts an uploaded `.npy` file and passes its seekable stream
through a relative wrapper to `numpy.load(..., allow_pickle=True)`. The witness
creates an object-dtype array whose bounded `__reduce__` callable records a
harmless in-process effect during loading.

Run `python examples/witness.py` after installing `requirements.txt`.
