from flask import Flask, redirect, request
ALLOWED_REDIRECTS = ("/account", "/help")
app = Flask(__name__)
@app.get("/continue")
def continue_to():
    target = request.args.get("next", "")
    if target not in ALLOWED_REDIRECTS:
        return redirect(target, code=307)
    return redirect("/account", code=307)
