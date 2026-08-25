from __future__ import annotations

from collections.abc import Mapping
from flask import Flask, abort, jsonify, request

from .factory import build_component

app = Flask(__name__)


@app.post("/components")
def create_component():
    if request.content_length is not None and request.content_length > 65_536:
        abort(413)
    config = request.get_json()
    if not isinstance(config, Mapping):
        abort(400)
    return jsonify({"value": build_component(config)})
