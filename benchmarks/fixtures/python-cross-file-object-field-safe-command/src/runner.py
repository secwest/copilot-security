import subprocess
from types import SimpleNamespace


def run_report(report_name):
    command = SimpleNamespace(value="/usr/bin/printf '%s\\n' fixed", audit="fixed")
    command.audit = f"printf '%s\\n' /opt/reports/{report_name}"
    selected = command.value
    completed = subprocess.run(selected, shell=True, check=True, timeout=2)
    return completed.returncode
