# Python tarfile unsafe extraction

This Flask fixture passes an uploaded tar stream through `extract_archive` to
the Python 3.12 `tarfile` default extraction policy. That default is equivalent
to `fully_trusted`, so a `../escaped-marker.txt` member writes outside the
selected destination.

Run `python examples/witness.py` from this fixture directory to reproduce the
bounded write inside a disposable temporary directory.
