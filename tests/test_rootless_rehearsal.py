import json
import subprocess
from pathlib import Path


def test_rootless_namespace_install_lifecycle(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    evidence = tmp_path / "rootless-rehearsal.json"
    result = subprocess.run(
        ["/usr/bin/python3", str(repo / "tools/rootless_namespace_rehearsal.py"),
         "--repo", str(repo), "--evidence", str(evidence)],
        text=True, capture_output=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(evidence.read_text())
    assert payload["schema"] == "hermes-rootless-rehearsal-v1"
    assert payload["namespace"] == {
        "host_root": "read-only", "network": "private", "pid": "private",
        "privilege": "unprivileged-user-namespace",
    }
    assert payload["operation"] == {
        "executable": "/usr/bin/id", "executions": 1,
        "flow": ["requester-submit", "telegram-publish", "captain-callback", "operator-approve", "requester-consume", "result"],
        "result_state": "succeeded",
    }
    assert payload["telegram_remote"] == "mocked"
    assert payload["replay"] == "denied"
    assert payload["restart_grant"] == "revoked"
    assert payload["sockets"] == {
        "operator.sock": {"gid": 2102, "mode": "0660", "uid": 0},
        "request.sock": {"gid": 2101, "mode": "0660", "uid": 0},
    }
    assert payload["uninstall"] == {"preserved": ["/var/lib/hermes-privilege-broker/ledger.sqlite"], "residue": []}
    assert payload["failed_apply"] == {"preserved": ["/var/lib/hermes-privilege-broker/ledger.sqlite"], "residue": []}
