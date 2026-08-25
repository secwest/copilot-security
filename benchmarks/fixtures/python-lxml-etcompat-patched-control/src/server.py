from flask import Flask, request

from .parser import parse_document

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


@app.post("/documents/import")
def import_document():
    values = parse_document(request.files["document"].read())
    return {"values": values}
