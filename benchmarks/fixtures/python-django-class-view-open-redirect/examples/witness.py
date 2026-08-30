from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from django.conf import settings


settings.configure(
    ALLOWED_HOSTS=["testserver"],
    MIDDLEWARE=[],
    ROOT_URLCONF="src.urls",
    SECRET_KEY="fixture-only",
)

import django


django.setup()

from django.test import Client


selected = "/attacker.invalid/capture?campaign=django-class-view"
response = Client().get("/continue/", {"next": selected}, follow=False)
location = response.headers["location"]
resolved = urlsplit(urljoin("https://scanner.invalid/start", location))
assert response.status_code == 302
assert location == "//attacker.invalid/capture?campaign=django-class-view"
assert resolved.scheme == "https"
assert resolved.netloc == "attacker.invalid"
print({"control": False, "attacker_origin_selected": 1})
