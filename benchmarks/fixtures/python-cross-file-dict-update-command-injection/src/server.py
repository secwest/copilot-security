from flask import Flask, request

from .runner import run_report

app = Flask(__name__)


@app.get("/report")
def report():
    report_name = request.args.get("name", "")
    return run_report(report_name)
