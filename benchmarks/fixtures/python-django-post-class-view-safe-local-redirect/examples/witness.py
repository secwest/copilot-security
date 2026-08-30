from pathlib import Path
import sys


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


selected = "/attacker.invalid/capture?campaign=django-post-class-view"
response = Client().post("/continue/", {"next": selected}, follow=False)
location = response.headers["location"]
assert response.status_code == 302
assert location == (
    "/continue/?next=%2Fattacker.invalid%2Fcapture%3Fcampaign%3Ddjango-post-class-view"
)
assert not location.startswith("//")
print({"control": True, "attacker_origin_selected": 0})
