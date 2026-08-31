from urllib.parse import quote
from flask import Blueprint, redirect, request

bp = Blueprint("redirects", __name__)

@bp.get("/continue")
def continue_to():
    target = request.args.get("next", "")
    encoded = quote(target, safe="")
    destination = "/continue?next=" + encoded
    return redirect(destination, code=307)
