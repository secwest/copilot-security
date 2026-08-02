import requests

MAX_PREVIEW_BYTES = 64 * 1024


def fetch_preview(target):
    with requests.get(target, stream=True, timeout=(2, 2)) as response:
        return read_limited_body(response)


def read_limited_body(response):
    chunks = []
    length = 0
    for chunk in response.iter_content(chunk_size=8 * 1024):
        length += len(chunk)
        if length > MAX_PREVIEW_BYTES:
            raise ValueError("preview response exceeds size limit")
        chunks.append(chunk)
    return b"".join(chunks)
