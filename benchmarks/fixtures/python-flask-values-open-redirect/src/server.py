from flask import Flask, redirect, request

app = Flask(__name__)


@app.get("/continue")
def continue_to():
    target = request.values.get("next", "")
    return redirect(target, code=307)
