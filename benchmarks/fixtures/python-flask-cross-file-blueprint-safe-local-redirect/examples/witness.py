from pathlib import Path
import sys


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture / "src"))

from service import create_app


selected = "/attacker.invalid/capture?campaign=flask-cross-file-blueprint"
response = create_app().test_client().get(
    "/links/continue", query_string={"next": selected}, follow_redirects=False
)
location = response.headers["location"]
assert response.status_code == 307
assert location == (
    "/continue?next=%2Fattacker.invalid%2Fcapture%3Fcampaign%3Dflask-cross-file-blueprint"
)
assert not location.startswith("//")
print({"control": True, "attacker_origin_selected": 0})
