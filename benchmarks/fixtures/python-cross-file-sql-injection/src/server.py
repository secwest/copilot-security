from flask import Flask, request

from .users import find_user

app = Flask(__name__)


@app.get("/users/lookup")
def user_lookup():
    email = request.args.get("email", "")
    return find_user(email)
