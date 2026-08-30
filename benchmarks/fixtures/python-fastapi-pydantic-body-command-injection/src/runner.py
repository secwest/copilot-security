import subprocess


def run_report(report_name: str) -> int:
    completed = subprocess.run(f"printf '%s\\n' /opt/reports/{report_name}", shell=True, check=True, timeout=2)
    return completed.returncode
