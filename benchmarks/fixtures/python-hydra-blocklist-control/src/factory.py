from __future__ import annotations

from hydra.utils import instantiate


def build_component(config):
    return instantiate(config)
