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

## Status

M1 complete — dual-server differential runs the full gloas suite both presets; private.
