from typing import Annotated
from urllib.parse import quote

from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse


app = FastAPI()


@app.get("/response-class", response_class=RedirectResponse, status_code=307)
def continue_to(next_url: Annotated[str, Query()]):
    destination = "/continue?next=" + quote(next_url, safe="")
    return destination
