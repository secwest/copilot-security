from flask import Flask, request

from .upstream import fetch_preview

app = Flask(__name__)


@app.get("/preview")
def preview():
    asset = request.args.get("asset", "")
    return fetch_preview(asset)
