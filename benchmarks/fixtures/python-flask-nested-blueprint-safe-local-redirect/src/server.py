from urllib.parse import quote

from flask import Blueprint, Flask, redirect, request

app = Flask(__name__)
parent = Blueprint("parent", __name__, url_prefix="/parent")
child = Blueprint("child", __name__, url_prefix="/child")


@child.get("/continue")
def continue_to():
    target = request.args.get("next", "")
    encoded = quote(target, safe="")
    destination = "/continue?next=" + encoded
    return redirect(destination, code=307)


parent.register_blueprint(child)
app.register_blueprint(parent)
