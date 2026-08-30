import subprocess


def run_report(report_name):
    commands = {"preview": "/usr/bin/printf '%s\\n' fixed", "audit": "fixed"}
    commands.update({"audit": f"printf '%s\\n' /opt/reports/{report_name}"})
    selected = commands.get("preview")
    completed = subprocess.run(selected, shell=True, check=True, timeout=2)
    return completed.returncode
