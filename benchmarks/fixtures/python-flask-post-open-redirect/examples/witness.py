from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from src.server import app


selected = "/attacker.invalid/capture?campaign=flask-post-form"
response = app.test_client().post(
    "/continue", data={"next": selected}, follow_redirects=False
)
location = response.headers["location"]
resolved = urlsplit(urljoin("https://scanner.invalid/start", location))
assert response.status_code == 307
assert location == "//attacker.invalid/capture?campaign=flask-post-form"
assert resolved.scheme == "https"
assert resolved.netloc == "attacker.invalid"
print({"control": False, "attacker_origin_selected": 1})
