import numpy as np


def parse_array(document):
    return np.load(document, allow_pickle=False)
