"""consensus-diff pytest driver.

One warm server per backend per xdist worker (session fixture); one test per
vector case; census records ride TestReport.user_properties to the xdist
controller, which writes one YAML stream + summary per run.

Known, accepted behavior: a mid-run respawn failure (HandshakeError from
ServerClient.submit) propagates and errors the case loudly — environmental
collapse should abort a sweep, not fabricate per-case verdicts.
"""

import datetime
import importlib.util
import os
import tomllib
from pathlib import Path

import pytest

from consensus_diff.backends import BackendSpec, ServerClient
from consensus_diff.compare import classify
from consensus_diff.report import render_summary, write_census
from consensus_diff.vectors import PINNED_TAG, Case, ensure_archive, prepare, walk_cases

# The schema lane needs the out-of-band pyspec (eth_consensus_specs, see README):
# no PyPI release carries gloas at the pinned tag, so a bare `uv sync` env lacks it.


def _pyspec_available() -> bool:
    """True iff the pyspec is installed for the fork the schema lane uses.

    Check the fork submodule, not just the top package: Schema.__init__ imports
    ``eth_consensus_specs.<fork>.<preset>``, so a stale/partial install with the
    top package but no gloas would slip past a top-level check and fail late in
    Schema instead of skipping cleanly (coderabbit review). ``find_spec`` on a
    dotted name *raises* ModuleNotFoundError when the top package is absent (the
    common "no pyspec" case) rather than returning None, so treat that as missing.
    It decides without importing the heavy fork module.
    """
    try:
        return importlib.util.find_spec("eth_consensus_specs.gloas") is not None
    except ModuleNotFoundError:
        return False


# Shared skip mark: module-level via `pytestmark`, per-test via `@requires_pyspec`.
requires_pyspec = pytest.mark.skipif(
    not _pyspec_available(),
    reason="needs the out-of-band pyspec (eth_consensus_specs); see README",
)

_census_records: list[dict] = []  # populated on the xdist controller (workers' copies unused)


def pytest_addoption(parser):
    parser.addoption("--backends", default="backends.toml",
                     help="TOML registry of backends (need >=2 supporting the fork/preset)")
    parser.addoption("--fork", default="gloas")
    parser.addoption("--preset", default="minimal")
    parser.addoption("--subset", type=int, default=2,
                     help="cases per (runner, handler); 0 = full suite")
    parser.addoption("--tag", default=PINNED_TAG)
    parser.addoption("--vector-root", default=None,
                     help="pre-extracted vector root (tests/... inside); skips download")
    parser.addoption("--report-dir", default="reports")


def _selected_specs(config) -> list[BackendSpec]:
    fork, preset = config.getoption("--fork"), config.getoption("--preset")
    try:
        specs = [s for s in BackendSpec.load_all(Path(config.getoption("--backends")))
                 if fork in s.forks and preset in s.presets]
    except (FileNotFoundError, ValueError) as e:
        raise pytest.UsageError(str(e)) from e
    if len(specs) < 2:
        raise pytest.UsageError(
            f"need >=2 backends supporting fork={fork} preset={preset}, got "
            f"{[s.name for s in specs]} — consensus-diff is strictly differential")
    return specs


def pytest_generate_tests(metafunc):
    if "diff_case" not in metafunc.fixturenames:
        return
    config = metafunc.config
    _selected_specs(config)  # raises UsageError at collection if <2 backends or registry broken
    fork = config.getoption("--fork")
    preset = config.getoption("--preset")
    root = config.getoption("--vector-root")
    root = Path(root) if root else ensure_archive(config.getoption("--tag"), preset)
    cases = list(walk_cases(root, preset, fork, subset=config.getoption("--subset")))
    if not cases:
        raise pytest.UsageError(
            f"no cases found under {root} for {preset}/{fork} — wrong --vector-root or fork?")
    metafunc.parametrize("diff_case", cases, ids=[c.id for c in cases])


@pytest.fixture(scope="session")
def servers(request):
    config = request.config
    specs = _selected_specs(config)
    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    log_dir = Path(config.getoption("--report-dir")) / "logs" / worker
    clients: dict[str, ServerClient] = {}
    try:
        for s in specs:
            clients[s.name] = ServerClient(s, config.getoption("--fork"),
                                           config.getoption("--preset"), log_dir)
    except Exception:
        for c in clients.values():
            c.close()
        raise
    yield clients
    for c in clients.values():
        c.close()


@pytest.fixture(scope="session")
def known_ids(request):
    p = Path(request.config.rootpath) / "known-divergences.toml"
    if not p.exists():
        return frozenset()
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    return frozenset(e["id"] for e in data.get("known", []))


@pytest.fixture
def agreement(diff_case: Case, servers, known_ids, tmp_path, record_property):
    request_obj = prepare(diff_case, tmp_path)
    line = request_obj.line()
    raw = {name: client.submit(line) for name, client in servers.items()}
    canon = {name: servers[name].spec.canonicalize(v) for name, v in raw.items()}
    ag = classify(canon, known_ids=known_ids, case_id=diff_case.id)
    record_property("census", {
        "id": diff_case.id, "class": ag.cls, "reason": ag.reason,
        "verdicts": {n: {"status": raw[n].status, "bucket": raw[n].bucket,
                         "canonical": canon[n].bucket, "detail": raw[n].detail}
                     for n in raw},
    })
    return ag


def pytest_runtest_logreport(report):
    if report.when != "call":
        return
    for name, value in report.user_properties:
        if name == "census":
            _census_records.append(value)


def pytest_sessionfinish(session):
    config = session.config
    if hasattr(config, "workerinput"):  # xdist worker: the controller owns the report
        return
    if not _census_records:
        return
    records = sorted(_census_records, key=lambda r: r["id"])
    fork, preset = config.getoption("--fork"), config.getoption("--preset")
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    outdir = Path(config.getoption("--report-dir"))
    write_census(records, outdir / f"{stamp}-{fork}-{preset}.yaml")
    (outdir / f"{stamp}-{fork}-{preset}-summary.md").write_text(
        render_summary(records, fork=fork, preset=preset), encoding="utf-8")
