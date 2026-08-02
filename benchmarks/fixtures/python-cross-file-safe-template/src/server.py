from flask import Flask, request

from .template import render_profile

app = Flask(__name__)


@app.post("/preview")
def preview():
    name = request.form.get("name", "")
    return render_profile(name)
