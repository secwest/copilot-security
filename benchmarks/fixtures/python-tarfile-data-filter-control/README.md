# Python tarfile data-filter control

This Flask fixture preserves the uploaded stream, wrapper, destination, and
extraction operation while passing `filter="data"`. It also streams through a
32-member preflight, bounds each regular file to 1 MiB and total expanded data
to 2 MiB, rejects links, special files, duplicate and case-colliding names,
and passes the already bounded member list to extraction. Python rejects the
same `../escaped-marker.txt` member before it can write outside the destination.

Run `python examples/witness.py` from this fixture directory to reproduce the
bounded rejection inside a disposable temporary directory.

Run `python examples/resource_witness.py` to exercise one valid archive plus
the member-count, per-member, cumulative-expanded-byte, link, and duplicate-
name rejection boundaries. It also uses only in-memory archives and disposable
temporary directories.
