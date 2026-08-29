import subprocess


def run_report(report_name):
    commands = []
    commands += [f"printf '%s\\n' /opt/reports/{report_name}"]
    completed = subprocess.run(commands[0], shell=True, check=True, timeout=2)
    return completed.returncode
