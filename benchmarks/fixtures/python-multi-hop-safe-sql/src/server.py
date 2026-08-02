from flask import Flask, request

from .service import lookup_user

app = Flask(__name__)


@app.get("/users/lookup")
def user_lookup():
    email = request.args.get("email", "")
    return lookup_user(email)
