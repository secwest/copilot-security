from flask import render_template_string


def render_template_source(template_source):
    return render_template_string(template_source)
