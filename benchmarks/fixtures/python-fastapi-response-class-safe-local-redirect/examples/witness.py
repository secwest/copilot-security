from pathlib import Path
import sys


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from fastapi.testclient import TestClient

from src.server import app


selected = "https://attacker.invalid/capture?campaign=response-class"
response = TestClient(app).get(
    "/response-class", params={"next_url": selected}, follow_redirects=False
)
assert response.status_code == 307
assert response.headers["location"].startswith("/continue?next=")
assert response.headers["location"] == (
    "/continue?next=https%3A%2F%2Fattacker.invalid%2Fcapture%3Fcampaign%3Dresponse-class"
)
print({"control": True, "response_class": True, "attacker_origin_selected": 0})
