from typing import Annotated

from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse


app = FastAPI()


@app.get(
    "/response-class",
    response_class=RedirectResponse,
    status_code=307,
)
def continue_to(next_url: Annotated[str, Query()]):
    destination = next_url
    return destination
