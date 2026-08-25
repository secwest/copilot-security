# Runtime validation contract

The bounded witness is regression-tested with the same `joblib==1.5.3`
dependency on both supported fixture environments:

- Python 3.12.3 on Linux/WSL;
- Python 3.14.5 on Windows.

These versions establish reproducible fixture behavior. They do not prove the
version deployed by a repository under scan unless that repository supplies
its own runtime evidence.
