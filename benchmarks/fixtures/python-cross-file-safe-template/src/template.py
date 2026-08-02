from jinja2 import Environment, select_autoescape

ENVIRONMENT = Environment(
    autoescape=select_autoescape(default_for_string=True, default=True)
)
PROFILE_TEMPLATE = ENVIRONMENT.from_string("<p>{{ name }}</p>")


def render_profile(name):
    return PROFILE_TEMPLATE.render(name=name)
