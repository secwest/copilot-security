# NumPy no-pickle control benchmark

This control keeps the same uploaded `.npy` source, wrapper topology, NumPy
binding, and executable witness, but passes `allow_pickle=False`. NumPy must
reject the object-dtype payload before the recorded callable can execute.

The route and parser retain the positive fixture's request, byte, header, rank,
and element-count budgets so the negative case differs only at the pickle
execution boundary.

Run `python examples/witness.py` after installing `requirements.txt`.
