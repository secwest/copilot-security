from pathlib import Path
import sys


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from fastapi.testclient import TestClient

from src.server import app


selected = "https://attacker.invalid/capture?campaign=redirect"
response = TestClient(app).get(
    "/login", params={"next_url": selected}, follow_redirects=False
)
assert response.status_code == 307
assert response.headers["location"] == selected
print({"control": False, "attacker_origin_selected": 1})
