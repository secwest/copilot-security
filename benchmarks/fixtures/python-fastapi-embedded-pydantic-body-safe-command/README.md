# FastAPI embedded Pydantic body ClassVar control

This topology-matched control retains the official FastAPI POST route, exact
`Annotated[ReportRequest, Body(embed=True)]` request body, hostile declared
string field, relative wrapper, and real `shell=True` sink. The endpoint
selects `payload.fixed_command`, an exact `typing.ClassVar` excluded from
Pydantic request-body fields, instead of the attacker-controlled
`payload.name`. Its witness must leave the disposable temporary marker absent.
