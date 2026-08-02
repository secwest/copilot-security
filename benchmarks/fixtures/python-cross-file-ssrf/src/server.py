from flask import Flask, request

from .upstream import fetch_preview

app = Flask(__name__)


@app.get("/preview")
def preview():
    target = request.args.get("url", "")
    return fetch_preview(target)
