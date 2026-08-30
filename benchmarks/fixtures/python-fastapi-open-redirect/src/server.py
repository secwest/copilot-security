from typing import Annotated

from fastapi import FastAPI, Query
from .redirects import issue_redirect


app = FastAPI()


@app.get("/login")
def login(next_url: Annotated[str, Query()]):
    destination = next_url
    return issue_redirect(destination)
