from typing import ClassVar

from pydantic import BaseModel


class ReportRequest(BaseModel):
    name: str
    fixed_command: ClassVar[str] = "status"
