from __future__ import annotations

from flask import Flask, abort, jsonify, request

from .loader import run_statechart

app = Flask(__name__)


@app.post("/statecharts/run")
def run_uploaded_statechart():
    if request.content_length is not None and request.content_length > 32_768:
        abort(413)
    document = request.get_data(as_text=True)
    if not document.strip():
        abort(400)
    return jsonify({"result": run_statechart(document)})
