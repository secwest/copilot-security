import subprocess


def run_report(report_name):
    completed = subprocess.run(
        ["/usr/bin/printf", "%s", report_name],
        check=True,
        shell=False,
        timeout=2,
    )
    return completed.returncode
