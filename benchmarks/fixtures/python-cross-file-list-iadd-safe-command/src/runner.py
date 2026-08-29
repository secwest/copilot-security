import subprocess


def run_report(report_name):
    commands = []
    commands += ["/usr/bin/printf", "%s\\n", f"/opt/reports/{report_name}"]
    completed = subprocess.run(commands, shell=False, check=True, timeout=2)
    return completed.returncode
