import subprocess
from dataclasses import dataclass


@dataclass
class ReportCommand:
    value: str
    audit: str


def run_report(report_name: str) -> int:
    command = ReportCommand(value="/usr/bin/printf fixed", audit="audit")
    command.audit = f"printf '%s\\n' /opt/reports/{report_name}"
    selected = command.value
    completed = subprocess.run(selected, shell=True, check=True, timeout=2)
    return completed.returncode
