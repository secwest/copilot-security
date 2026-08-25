from flask import Flask, request

from .parser import parse_array

app = Flask(__name__)


@app.post("/arrays/import")
def import_array():
    return {"shape": parse_array(request.files["array"].stream).shape}
