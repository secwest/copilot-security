from pathlib import Path
import sys


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from src.server import app


selected = "https://attacker.invalid/capture?campaign=flask-builtin-str"
response = app.test_client().get(
    "/continue", query_string={"next": selected}, follow_redirects=False
)
location = response.headers["location"]
assert response.status_code == 307
assert location == "/account"
assert not location.startswith("https://attacker.invalid/")
print({"control": True, "attacker_origin_selected": 0, "builtin_str": True})
