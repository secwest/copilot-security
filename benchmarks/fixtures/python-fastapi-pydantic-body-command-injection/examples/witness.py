from pathlib import Path
import shlex
import sys
import tempfile


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from fastapi.testclient import TestClient

from src.server import app


with tempfile.TemporaryDirectory(prefix="copilot-security-pydantic-body-flow-") as temporary:
    marker = Path(temporary) / "shell-expanded"
    payload = f"baseline; printf exploited > {shlex.quote(str(marker))}"
    response = TestClient(app).post("/report", json={"name": payload})
    shell_expanded = marker.read_text(encoding="utf-8") == "exploited"
    assert response.status_code == 200
    assert response.json() == 0
    assert shell_expanded
    print({"control": False, "shell_expanded_marker": 1})
