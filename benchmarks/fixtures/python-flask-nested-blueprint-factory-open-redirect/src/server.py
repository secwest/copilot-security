from urllib.parse import quote

from flask import Blueprint, Flask, redirect, request

parent = Blueprint("parent", __name__, url_prefix="/parent")
child = Blueprint("child", __name__, url_prefix="/child")


@child.get("/continue")
def continue_to():
    target = request.args.get("next", "")
    encoded = target
    destination = "/" + encoded
    return redirect(destination, code=307)


parent.register_blueprint(child)


def create_app():
    app = Flask(__name__)
    app.register_blueprint(parent, url_prefix="/root")
    return app
