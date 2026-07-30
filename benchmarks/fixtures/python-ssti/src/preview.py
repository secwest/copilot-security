from flask import request
from jinja2 import Environment


environment = Environment()


def preview_notification():
    template_source = request.get_json()["template"]
    template = environment.from_string(template_source)
    return template.render(
        user={"name": request.user.display_name},
        support_email="support@example.test",
    )
