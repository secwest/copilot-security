from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from src.server import create_app


app = create_app()
selected = "/attacker.invalid/capture?campaign=flask-nested-blueprint-factory"
response = app.test_client().get(
    "/root/child/continue",
    query_string={"next": selected},
    follow_redirects=False,
)
location = response.headers["location"]
resolved = urlsplit(urljoin("https://scanner.invalid/start", location))
assert response.status_code == 307
assert location.startswith("/continue?next=")
assert "attacker.invalid" in location
assert resolved.scheme == "https"
assert resolved.netloc == "scanner.invalid"
print({"control": True, "attacker_origin_selected": 0})
