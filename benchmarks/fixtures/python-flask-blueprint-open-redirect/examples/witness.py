from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from src.server import app


selected = "/attacker.invalid/capture?campaign=flask-blueprint"
response = app.test_client().get(
    "/continue", query_string={"next": selected}, follow_redirects=False
)
location = response.headers["location"]
resolved = urlsplit(urljoin("https://scanner.invalid/start", location))
assert response.status_code == 307
assert location == "//attacker.invalid/capture?campaign=flask-blueprint"
assert resolved.scheme == "https"
assert resolved.netloc == "attacker.invalid"
print({"control": False, "attacker_origin_selected": 1})
