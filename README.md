# consensus-diff

A differential conformance harness for Ethereum consensus clients. It drives N (≥2) client backends — each a subprocess speaking a shared wire protocol (see [docs/protocol.md](docs/protocol.md)) — over the consensus-spec-tests vectors, collects a verdict from each backend per test case, and flags any disagreement. The harness never judges against an expected-output file itself; agreement across clients is the criterion.

## Invocation

```sh
uv sync
meson setup build
meson test -C build --suite unit        # the harness's own tests — no backends needed
```

The differential sweeps need ≥2 backends. Build each one, then copy the
registry template and point it at your binaries:

```sh
cp backends.toml.example backends.toml   # backends.toml is gitignored (machine-specific paths)
# edit backends.toml — see the comments in the .example
ninja -C build diff-smoke                # gloas/minimal dev subset
```

The first sweep downloads and caches the consensus-spec-tests archive under
`~/.cache/consensus-diff/`. Full sweeps: `ninja -C build diff-full-minimal`
(and `diff-full-mainnet`); both run `-n 2` by default.

## License

Tri-licensed at your option:

- [CC0-1.0](CC0-1.0.md) — public-domain dedication, same as ethereum/consensus-specs.
- [Apache-2.0](Apache-2.0.md) — adds an express patent license from contributors, terminates on patent litigation.
- [WTFPL](WTFPL-2.0.md) — for good measure.

SPDX: `CC0-1.0 OR Apache-2.0 OR WTFPL`. No warranty under any option.

Inbound = outbound: contributions are licensed under all three options above. Every commit must carry a DCO sign-off (`git commit -s`, see [DCO.md](DCO.md)).

I hold no patents and do not intend to acquire any. — Ivan Anishchuk

## Fuzzing (M2 Phase 1, local/nightly)

Schema-aware, decode-valid mutation of operations seeds, run as a reject-class
differential: mutate a valid operand, drop the post state (protocol "expect
reject"), and count any accept/reject disagreement between backends as a
validity-boundary finding. Local / nightly only — never in CI.

`eth-remerkleable` is a base dependency, so a plain install already carries the
mutation machinery. The one out-of-band piece is the pyspec, which is not on PyPI
at the pinned tag and must be built by hand:

```sh
# 1. clone the pinned spec
git clone --depth 1 --branch v1.7.0-alpha.11 \
  https://github.com/ethereum/consensus-specs.git consensus-specs-v1.7.0-alpha.11
# 2. generate the spec package (from that clone)
( cd consensus-specs-v1.7.0-alpha.11 && uv sync && \
  uv run python -m pysetup.generate_specs --all-forks )
# 3. install it into consensus-diff's env
uv sync
uv pip install ./consensus-specs-v1.7.0-alpha.11
```

Gotcha: a bare `uv sync` uninstalls the out-of-band pyspec — re-run
`uv pip install <clone>` after any sync. Without it, the schema-lane tests are
skipped (a shared `requires_pyspec` marker) rather than erroring; the rest run.

Run:

```sh
uv run python -m consensus_diff.fuzz --fork=gloas --preset=minimal \
  --vector-root=~/.cache/consensus-diff/v1.7.0-alpha.11-minimal --iterations=1000
```

Output is a dated `reports/*-fuzz.md` with the deduplicated findings.

## Status

M1 complete — dual-server differential runs the full gloas suite both presets; private.
