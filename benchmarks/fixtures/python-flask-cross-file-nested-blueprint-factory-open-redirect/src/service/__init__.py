from flask import Flask


def create_app():
    app = Flask(__name__)
    from . import parent as routes
    app.register_blueprint(routes.parent, url_prefix="/root")
    return app
