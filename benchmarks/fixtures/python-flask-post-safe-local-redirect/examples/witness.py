from pathlib import Path
import sys


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from src.server import app


selected = "/attacker.invalid/capture?campaign=flask-post-form"
response = app.test_client().post(
    "/continue", data={"next": selected}, follow_redirects=False
)
location = response.headers["location"]
assert response.status_code == 307
assert location == (
    "/continue?next=%2Fattacker.invalid%2Fcapture%3Fcampaign%3Dflask-post-form"
)
assert not location.startswith("//")
print({"control": True, "attacker_origin_selected": 0})
