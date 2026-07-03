"""Backend registry (backends.toml) and warm wire-protocol servers.

Divergences by design from the harness behavior this reimplements the role of
(see the design doc): per-case timeout instead of an unbounded read; stderr to
a per-backend log file instead of the null device; death -> respawn once and
resend once, then a synthesized infra verdict.
"""

import os
import queue
import subprocess
import threading
import time
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from consensus_diff.protocol import Verdict

_EOF = object()


class HandshakeError(RuntimeError):
    """The backend process could not start at all (bad argv, exit 2, ...)."""


@dataclass(frozen=True)
class BackendSpec:
    name: str
    cmd: tuple[str, ...]
    cwd: Path | None
    env: dict[str, str]
    forks: frozenset[str]
    presets: frozenset[str]
    timeout: float = 300.0
    handshake_grace: float = 2.0
    buckets: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load_all(cls, path: Path) -> list["BackendSpec"]:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        specs = []
        for name, b in data.get("backends", {}).items():
            try:
                specs.append(cls(
                    name=name,
                    cmd=tuple(b["cmd"]),
                    cwd=Path(b["cwd"]).expanduser() if "cwd" in b else None,
                    env={k: str(v) for k, v in b.get("env", {}).items()},
                    forks=frozenset(b["forks"]),
                    presets=frozenset(b["presets"]),
                    timeout=float(b.get("timeout", 300.0)),
                    handshake_grace=float(b.get("handshake_grace", 2.0)),
                    buckets=dict(b.get("buckets", {})),
                ))
            except KeyError as e:
                raise ValueError(
                    f"{path}: [backends.{name}] missing required key {e}"
                ) from e
        if not specs:
            raise ValueError(f"{path}: no [backends.<name>] tables")
        return specs

    def argv(self, fork: str, preset: str) -> list[str]:
        """Substitute {fork}/{preset} placeholders, then append the protocol positionals."""
        subst = [t.format(fork=fork, preset=preset) for t in self.cmd]
        return [*subst, fork, preset]

    def canonicalize(self, verdict: Verdict) -> Verdict:
        """Remap a raw backend bucket to the canonical vocabulary via this
        backend's alias table (identity when unlisted). The alias table lets
        independently-developed backends emit their own dialect while the
        differential compares one shared vocabulary (docs/protocol.md §5)."""
        alias = self.buckets.get(verdict.bucket)
        return verdict if alias is None else replace(verdict, bucket=alias)


class ServerClient:
    """One warm backend process; spawn/respawn, submit with timeout.

    Not thread-safe: one caller per client. A closed client cannot be reused.
    """

    def __init__(self, spec: BackendSpec, fork: str, preset: str, log_dir: Path) -> None:
        self.spec = spec
        self.fork = fork
        self.preset = preset
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        self._log_path = Path(log_dir) / f"{spec.name}.stderr.log"
        self._proc: subprocess.Popen | None = None
        self._closed = False
        self._lines: queue.Queue = queue.Queue()
        self._spawn(initial=True)

    def _spawn(self, initial: bool = False) -> None:
        env = os.environ | self.spec.env
        log = open(self._log_path, "ab")
        self._lines = queue.Queue()
        try:
            self._proc = subprocess.Popen(
                self.spec.argv(self.fork, self.preset),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                cwd=self.spec.cwd, env=env, text=True, bufsize=1,
            )
        except OSError as e:
            raise HandshakeError(f"{self.spec.name}: cannot spawn: {e}") from e
        finally:
            log.close()  # Popen dup'd the fd; close our copy either way
        # Deviation from listing: pass the queue as a parameter so each reader
        # thread is bound to its own queue at spawn time, eliminating the race
        # where a late put from an old reader thread could write to the new queue
        # (since self._lines is swapped above before the thread starts).
        threading.Thread(
            target=self._read_stdout, args=(self._proc, self._lines), daemon=True
        ).start()
        if initial:
            # wait() is event-driven: it returns the instant the child exits, up to
            # the timeout ceiling.  A bad-argv / unsupported-fork backend exits 2
            # almost immediately (fast path), so wait() catches it quickly regardless
            # of the grace value.  The grace is only the assume-healthy ceiling before
            # a healthy (never-exiting) backend is declared up.  It must therefore
            # exceed worst-case interpreter cold-start-to-exit under heavy load
            # (hence 2.0 s default, not 0.5 s).  Per-backend so unit fakes can use a
            # short grace (e.g. 0.3 s) and the suite stays fast.
            grace = self.spec.handshake_grace
            try:
                code = self._proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass  # alive after the grace window: handshake ok
            else:
                raise HandshakeError(
                    f"{self.spec.name}: exited {code} at startup within the "
                    f"{grace}s handshake window "
                    f"(unsupported fork/preset or bad argv); stderr: {self._log_path}"
                )

    def _read_stdout(self, proc: subprocess.Popen, lines: queue.Queue) -> None:
        for raw in proc.stdout:
            lines.put(raw)
        lines.put(_EOF)

    def _kill(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.kill()
            self._proc.wait()
        self._proc = None

    def submit(self, line: str) -> Verdict:
        """One request line -> one verdict; respawn+resend at most once on death."""
        if self._closed:
            raise RuntimeError(f"{self.spec.name}: submit() after close()")
        for attempt in (1, 2):
            if self._proc is None or self._proc.poll() is not None:
                self._spawn()
            try:
                # At most one unanswered line is ever in flight and request lines are far
                # below the 64 KiB pipe buffer, so this write cannot block; revisit if
                # the protocol ever batches or inlines payloads.
                self._proc.stdin.write(line + "\n")
                self._proc.stdin.flush()
            except OSError:
                self._kill()
                continue
            deadline = time.monotonic() + self.spec.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._kill()
                    return Verdict("fail", "bug",
                                   f"timeout after {self.spec.timeout:.0f}s; "
                                   f"server killed; stderr: {self._log_path}")
                try:
                    raw = self._lines.get(timeout=min(remaining, 1.0))
                except queue.Empty:
                    continue
                if raw is _EOF:
                    break
                v = Verdict.try_parse(raw)
                if v is not None:
                    return v
                # non-protocol noise: drain and keep waiting
            self._kill()
        return Verdict("fail", "bug",
                       f"server died twice on this case; stderr: {self._log_path}")

    def close(self) -> None:
        """EOF on stdin asks for shutdown; 30s grace, then kill."""
        if self._proc is not None and self._proc.poll() is None:
            try:
                self._proc.stdin.close()
                self._proc.wait(timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                self._kill()
        self._proc = None
        self._closed = True
