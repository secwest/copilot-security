# FastAPI embedded Pydantic body command injection

An official FastAPI POST path operation uses the documented exact
`Annotated[ReportRequest, Body(embed=True)]` form to bind the nested `payload`
JSON member to a Pydantic `BaseModel`. The endpoint reads the declared string
field `payload.name` and passes it through a relative wrapper into
`subprocess.run(..., shell=True)`. The witness proves only that POSIX shell
metacharacters from that embedded request-body field can create one disposable
temporary marker.
