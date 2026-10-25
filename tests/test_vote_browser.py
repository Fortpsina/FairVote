"""Exercise the actual JS submit handler, including a lost network response."""
import subprocess
from pathlib import Path

import pytest

from test_payload_js import _node


def test_browser_sends_district_preserves_retry_and_does_not_persist_secret():
    node = _node()
    if node is None:
        pytest.skip("node is not available")
    script = Path(__file__).resolve().parent.parent / "tools" / "check_vote_flow.js"
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
