# consensus-diff

A differential conformance harness for Ethereum consensus clients. It drives N (≥2) client backends — each a subprocess speaking a shared wire protocol (see [docs/protocol.md](docs/protocol.md)) — over the consensus-spec-tests vectors, collects a verdict from each backend per test case, and flags any disagreement. The harness never judges against an expected-output file itself; agreement across clients is the criterion.

## Invocation

```sh
uv sync
meson setup build
meson test -C build --suite unit
ninja -C build diff-smoke
```

## License

Tri-licensed at your option:

- [CC0-1.0](CC0-1.0.md) — public-domain dedication, same as ethereum/consensus-specs.
- [Apache-2.0](Apache-2.0.md) — adds an express patent license from contributors, terminates on patent litigation.
- [WTFPL](WTFPL-2.0.md) — for good measure.

SPDX: `CC0-1.0 OR Apache-2.0 OR WTFPL`. No warranty under any option.

Inbound = outbound: contributions are licensed under all three options above. Every commit must carry a DCO sign-off (`git commit -s`, see [DCO.md](DCO.md)).

I hold no patents and do not intend to acquire any. — Ivan Anishchuk

## Status

Pre-M1, private.
