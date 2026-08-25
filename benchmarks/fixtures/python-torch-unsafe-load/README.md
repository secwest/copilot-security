# Python PyTorch unsafe-load benchmark

The Flask route passes a bounded request-controlled checkpoint stream through
one relative wrapper into `torch.load(..., weights_only=False)`. That explicit
full-unpickler boundary allows pickle callable dispatch before the load
returns. The paired control preserves the route, request stream, wrapper, byte
budget, effect module, requirements, and checkpoint while changing only
`weights_only=False` to patched `weights_only=True`.

The witness invokes only the fixture-local `src.effects.mark` function. It does
not start a listener, access the network, invoke a shell, or write a file.
