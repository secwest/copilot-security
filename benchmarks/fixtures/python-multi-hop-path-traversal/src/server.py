from flask import Flask, request

from .gateway import route_document_read

app = Flask(__name__)


@app.get("/documents")
def get_document():
    name = request.args.get("path", "")
    return route_document_read(name)
