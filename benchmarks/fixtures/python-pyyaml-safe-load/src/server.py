from flask import Flask, request

from .parser import parse_profile

app = Flask(__name__)


@app.post("/profiles/import")
def import_profile():
    document = request.get_data(as_text=True)
    return {"profile": parse_profile(document)}
