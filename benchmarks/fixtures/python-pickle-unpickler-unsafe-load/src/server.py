from flask import Flask, request

from .parser import parse_profile

app = Flask(__name__)


@app.post("/profiles/import")
def import_profile():
    return {"profile": parse_profile(request.stream)}
