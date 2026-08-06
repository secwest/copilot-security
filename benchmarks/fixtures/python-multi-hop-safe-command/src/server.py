from flask import Flask, request

from .gateway import route_report

app = Flask(__name__)


@app.get("/report")
def report():
    report_name = request.args.get("name", "")
    return route_report(report_name)
