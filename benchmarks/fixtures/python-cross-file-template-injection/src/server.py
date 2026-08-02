from flask import Flask, request

from .template import render_template_source

app = Flask(__name__)


@app.post("/preview")
def preview():
    template_source = request.form.get("template", "")
    return render_template_source(template_source)
