from urllib.parse import quote

from flask import Flask, redirect, request

app = Flask(__name__)

@app.get("/continue")
def continue_to():
    target = request.args.get("next", "")
    destination = "/continue?next=" + quote(target, safe="")
    return redirect(destination, code=307)
