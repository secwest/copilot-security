# FastAPI Annotated Pydantic body command injection

An official FastAPI POST path operation uses the recommended exact
`Annotated[ReportRequest, Body()]` form to bind JSON request data to a Pydantic
`BaseModel`. The endpoint reads the declared string field `payload.name` and
passes it through a relative wrapper into `subprocess.run(..., shell=True)`.
The witness proves only that POSIX shell metacharacters from that request-body
field can create one disposable temporary marker.
