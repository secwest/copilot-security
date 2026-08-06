from .service import dispatch_report


def route_report(report_name):
    return dispatch_report(
        report_name,
    )
