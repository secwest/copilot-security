from flask import Flask, request

from .service import dispatch_report

app = Flask(__name__)


@app.get("/report")
def report():
    report_name = request.args.get("name", "")
    return dispatch_report(report_name)
