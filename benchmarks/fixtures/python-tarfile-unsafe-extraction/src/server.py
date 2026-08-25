from __future__ import annotations

from flask import Flask, abort, request

from .extractor import extract_archive

app = Flask(__name__)


@app.post("/archives")
def upload_archive():
    if request.content_length is not None and request.content_length > 1_048_576:
        abort(413)
    extract_archive(request.files["archive"].stream, "/srv/app/imports")
    return "", 204
