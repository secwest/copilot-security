from flask import Flask


def create_app():
    app = Flask(__name__)
    from . import redirects
    app.register_blueprint(redirects.bp, url_prefix="/links")
    return app
