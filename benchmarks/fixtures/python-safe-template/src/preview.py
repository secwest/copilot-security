from flask import request
from jinja2 import Environment, select_autoescape


environment = Environment(autoescape=select_autoescape(default=True))
notification_template = environment.from_string(
    "<p>Hello {{ display_name }}. Contact {{ support_email }} for help.</p>"
)


def preview_notification():
    display_name = request.get_json()["display_name"]
    return notification_template.render(
        display_name=display_name,
        support_email="support@example.test",
    )
