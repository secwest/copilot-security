from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/continue", methods=["POST"])
def continue_to():
    target = request.form.get("next", "")
    destination = "/" + target
    return redirect(destination, code=307)
