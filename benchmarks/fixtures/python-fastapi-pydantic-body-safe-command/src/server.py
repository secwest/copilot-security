from fastapi import FastAPI

from .models import ReportRequest
from .runner import run_report

app = FastAPI()


@app.post("/report")
def report(payload: ReportRequest) -> int:
    return run_report(payload.fixed_command)
