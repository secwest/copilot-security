import torch

MAX_MODEL_BYTES = 64 * 1024


def parse_model(document):
    start = document.tell()
    payload = document.read(MAX_MODEL_BYTES + 1)
    if len(payload) > MAX_MODEL_BYTES:
        raise ValueError("model upload exceeds byte limit")

    document.seek(start)
    return torch.load(document, map_location="cpu", weights_only=False)
