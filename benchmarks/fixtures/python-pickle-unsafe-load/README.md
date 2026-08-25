# Python pickle unsafe-load benchmark

The Flask route passes the raw request body through one relative wrapper into
standard-library `pickle.loads`. The paired control preserves the same request,
wrapper, effect module, and witness, but parses the bytes as JSON instead.

The witness invokes only the fixture-local `src.effects.mark` function during
unpickling. It does not start a listener, access the network, invoke a shell, or
write a file.
