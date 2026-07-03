import subprocess
import sys
import textwrap
from pathlib import Path

import cramjam
import yaml

REPO = Path(__file__).parent.parent
FAKE = Path(__file__).parent / "fake_backend.py"


def test_driver_end_to_end(tmp_path):
    root = tmp_path / "cache"
    for e in ["operations/attestation/s/c1", "operations/attestation/s/c2"]:
        d = root / "tests" / "minimal" / "gloas" / e
        d.mkdir(parents=True)
        (d / "pre.ssz_snappy").write_bytes(bytes(cramjam.snappy.compress_raw(b"PRE")))
    backends = tmp_path / "backends.toml"
    backends.write_text(textwrap.dedent(f"""
        [backends.alpha]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "ok" }}
        forks = ["gloas"]
        presets = ["minimal"]

        [backends.beta]
        cmd = ["{sys.executable}", "{FAKE}"]
        env = {{ FAKE_MODE = "reject" }}
        forks = ["gloas"]
        presets = ["minimal"]
    """))
    reports = tmp_path / "reports"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(REPO / "test_diff.py"), "-q",
         "-p", "no:cacheprovider",
         f"--backends={backends}", "--fork=gloas", "--preset=minimal",
         f"--vector-root={root}", f"--report-dir={reports}"],
        capture_output=True, text=True, cwd=REPO,
    )
    # alpha says pass/ok, beta says fail/reject -> every case disagrees -> failures
    assert "2 failed" in proc.stdout, proc.stdout + proc.stderr
    census = list(reports.glob("*-gloas-minimal.yaml"))
    assert census, (
        f"census stream not written; reports contains "
        f"{list(reports.iterdir()) if reports.exists() else 'nothing'}"
    )
    docs = list(yaml.safe_load_all(census[0].read_text()))
    assert {d["class"] for d in docs} == {"disagree"}
    assert list(reports.glob("*-summary.md")), "summary not written"
