from __future__ import annotations

from flask import Flask, jsonify, request

from .loader import compile_and_load

app = Flask(__name__)


@app.post("/models/compile")
def compile_model():
    schema = request.get_json(force=True)
    namespace = compile_and_load(schema)
    return jsonify({"symbols": sorted(namespace)})
