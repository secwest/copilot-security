from pathlib import Path
import shlex
import sys
import tempfile


fixture = Path(__file__).parents[1]
sys.path.insert(0, str(fixture))

from src.runner import run_report


with tempfile.TemporaryDirectory(prefix="copilot-security-dataclass-field-control-") as temporary:
    marker = Path(temporary) / "shell-expanded"
    payload = f"baseline; printf exploited > {shlex.quote(str(marker))}"
    return_code = run_report(payload)
    shell_expanded = marker.exists()
    assert return_code == 0
    assert not shell_expanded
    print({"control": True, "shell_expanded_marker": 0})
