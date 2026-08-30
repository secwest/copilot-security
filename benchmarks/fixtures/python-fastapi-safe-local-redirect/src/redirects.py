from fastapi.responses import RedirectResponse


def issue_redirect(destination: str) -> RedirectResponse:
    return RedirectResponse(url=destination, status_code=307)
