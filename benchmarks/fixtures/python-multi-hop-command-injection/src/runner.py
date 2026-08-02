import os


def run_report(report_name):
    return os.system(f"/opt/reports/{report_name}")
