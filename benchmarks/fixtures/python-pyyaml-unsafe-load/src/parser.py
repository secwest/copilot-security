import yaml


def parse_profile(document):
    return yaml.load(document, Loader=yaml.UnsafeLoader)
