from flask import Flask, request

from .parser import parse_array

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


@app.post("/arrays/import")
def import_array():
    return {"shape": parse_array(request.files["array"].stream).shape}
