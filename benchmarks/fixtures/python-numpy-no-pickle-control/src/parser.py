import math

import numpy as np

MAX_ARRAY_BYTES = 64 * 1024
MAX_ARRAY_DIMENSIONS = 2
MAX_ARRAY_ELEMENTS = 16


def parse_array(document):
    start = document.tell()
    payload = document.read(MAX_ARRAY_BYTES + 1)
    if len(payload) > MAX_ARRAY_BYTES:
        raise ValueError("array upload exceeds byte limit")

    document.seek(start)
    if np.lib.format.read_magic(document) != (1, 0):
        raise ValueError("only bounded NumPy 1.0 arrays are accepted")
    shape, _fortran_order, dtype = np.lib.format.read_array_header_1_0(
        document,
        max_header_size=1024,
    )
    if len(shape) > MAX_ARRAY_DIMENSIONS:
        raise ValueError("array rank exceeds limit")
    if math.prod(shape) > MAX_ARRAY_ELEMENTS:
        raise ValueError("array element count exceeds limit")
    if dtype.kind != "O":
        raise ValueError("only object-array imports are accepted")

    document.seek(start)
    return np.load(document, allow_pickle=False, max_header_size=1024)
