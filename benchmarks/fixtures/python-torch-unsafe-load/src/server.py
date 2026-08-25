from flask import Flask, request

from .parser import parse_model

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


@app.post("/models/import")
def import_model():
    model = parse_model(request.files["model"].stream)
    return {"type": type(model).__name__}
