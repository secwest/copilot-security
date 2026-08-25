from __future__ import annotations

from flask import Flask, abort, jsonify, request

from .parser import parse_expression

app = Flask(__name__)


@app.post("/verify/math")
def verify_math():
    if request.content_length is not None and request.content_length > 16_384:
        abort(413)
    expression = request.get_json()["expression"]
    if not isinstance(expression, str):
        abort(400)
    return jsonify({"value": str(parse_expression(expression))})
