from typing import Annotated
from urllib.parse import quote

from fastapi import FastAPI, Query
from .redirects import issue_redirect


app = FastAPI()


@app.get("/login")
def login(next_url: Annotated[str, Query()]):
    destination = "/continue?next=" + quote(next_url, safe="")
    return issue_redirect(destination)
