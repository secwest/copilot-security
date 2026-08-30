# FastAPI Pydantic request-body field command injection

An official FastAPI POST path operation binds JSON request data to an exact
Pydantic `BaseModel`. The endpoint reads the declared string field
`payload.name` and passes it through a relative wrapper into
`subprocess.run(..., shell=True)`. The witness proves only that POSIX shell
metacharacters from that request-body field can create one disposable temporary
marker.
