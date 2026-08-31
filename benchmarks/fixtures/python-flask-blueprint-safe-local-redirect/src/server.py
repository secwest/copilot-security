from urllib.parse import quote

from flask import Blueprint, Flask, redirect, request

app = Flask(__name__)
bp = Blueprint("redirects", __name__)

@bp.get("/continue")
def continue_to():
    target = request.args.get("next", "")
    destination = "/continue?next=" + quote(target, safe="")
    return redirect(destination, code=307)

app.register_blueprint(bp)
