"""The pyspec/remerkleable schema lane.

The ONLY module that imports the pyspec. Used to decode, re-serialize, and
hash_tree_root vector inputs so the fuzzer can produce decode-valid mutations.
It is never a judge: the two backends remain the sole verdict authorities
(design doc, neutrality guard).
"""

from importlib import import_module
from pathlib import Path

import cramjam

# (runner, handler) -> container class name in the fork's pyspec module.
# Extended in Task 3 to the full operations set.
_CONTAINER = {
    ("operations", "attestation"): "Attestation",
}


class Schema:
    def __init__(self, fork: str, preset: str) -> None:
        self._spec = import_module(f"eth_consensus_specs.{fork}.{preset}")

    def container_for(self, runner: str, handler: str) -> type:
        name = _CONTAINER[(runner, handler)]
        return getattr(self._spec, name)

    def decode(self, runner: str, handler: str, path: Path):
        raw = bytes(cramjam.snappy.decompress_raw(Path(path).read_bytes()))
        return self.container_for(runner, handler).decode_bytes(raw)

    def write(self, obj, path: Path) -> None:
        Path(path).write_bytes(bytes(cramjam.snappy.compress_raw(obj.encode_bytes())))

    def htr(self, obj) -> str:
        return obj.hash_tree_root().hex()
