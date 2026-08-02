from .runner import run_report


def dispatch_report(report_name):
    return run_report(
        report_name,
    )
