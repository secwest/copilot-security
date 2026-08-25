# Python Unpickler unsafe-load benchmark

The Flask route passes its request stream through one relative wrapper into the
file argument of standard-library `pickle.Unpickler`. The wrapper retains the
instance and later calls `load()`. The paired control preserves the request,
wrapper, effect module, and witness, but parses the same stream as JSON.

The witness invokes only the fixture-local `src.effects.mark` function during
unpickling. It does not start a listener, access the network, invoke a shell, or
write a file.
