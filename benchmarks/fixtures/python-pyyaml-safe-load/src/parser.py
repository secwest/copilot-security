import yaml


def parse_profile(document):
    return yaml.safe_load(document)
