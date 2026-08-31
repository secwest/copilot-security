from flask import Blueprint
from .child import child

parent = Blueprint("parent", __name__, url_prefix="/parent")
parent.register_blueprint(child, url_prefix="/child")
