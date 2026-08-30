from typing import Annotated

from fastapi import Body, FastAPI

from .models import ReportRequest
from .runner import run_report

app = FastAPI()


@app.post("/report")
def report(payload: Annotated[ReportRequest, Body(embed=True)]) -> int:
    return run_report(payload.name)
