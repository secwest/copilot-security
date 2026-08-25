# Python tarfile data-filter control

This Flask fixture preserves the uploaded stream, wrapper, destination, and
extraction operation while passing `filter="data"`. Python rejects the same
`../escaped-marker.txt` member before it can write outside the destination.

Run `python examples/witness.py` from this fixture directory to reproduce the
bounded rejection inside a disposable temporary directory.
