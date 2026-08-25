# NumPy no-pickle control benchmark

This control keeps the same uploaded `.npy` source, wrapper topology, NumPy
binding, and executable witness, but passes `allow_pickle=False`. NumPy must
reject the object-dtype payload before the recorded callable can execute.

Run `python examples/witness.py` after installing `requirements.txt`.
