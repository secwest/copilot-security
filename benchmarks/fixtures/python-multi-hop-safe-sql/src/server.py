from flask import Flask, request

from .gateway import route_user_lookup

app = Flask(__name__)


@app.get("/users/lookup")
def user_lookup():
    email = request.args.get("email", "")
    return route_user_lookup(email)
