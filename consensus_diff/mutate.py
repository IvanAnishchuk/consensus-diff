"""Deterministic mutation operators over typed SSZ objects.

Schema-aware operators perturb a leaf field to a semantic-edge value; the
byte-level complement (Task 5) reaches parser-boundary cases the typed path
cannot. Every operator is a pure function of (object, seeded RNG), so a finding
is fully described by its seed and replays exactly.

The introspection primitives (confirmed against eth-remerkleable==0.1.31):
  * ``type(container).fields()`` -> an ordered ``{name: type}`` map of a
    Container's fields, in declaration order.
  * ``getattr(container, name)`` reads a field; assigning through the chain
    (``container.data.slot = value``) propagates up to the parent's backing.
  * ``container.copy()`` returns an independent deep copy.
  * ``uint`` leaves carry ``type_byte_length()``; ``isinstance(v, uint)``
    identifies them and ``issubclass(t, Container)`` identifies sub-containers
    to recurse into. Bit(list|vector)s, byte vectors (roots, signatures), and
    SSZ lists/vectors are left to the byte-level path.
"""

import random
from dataclasses import dataclass

from remerkleable.basic import uint
from remerkleable.complex import Container


@dataclass(frozen=True)
class MutationOp:
    """A replayable record of one mutation: which leaf path, which new value."""

    path: tuple[str, ...]
    value: str  # repr of the injected value; evidence, never re-parsed


def _leaf_uint_paths(obj, prefix: tuple[str, ...] = ()):
    """Yield (path, current_value) for every uint leaf, depth-first, stable order.

    Order follows Container field-declaration order, so the same object always
    yields the same sequence -- the basis of the mutation's determinism.
    """
    for name, ftype in type(obj).fields().items():
        value = getattr(obj, name)
        if isinstance(value, uint):
            yield prefix + (name,), value
        elif issubclass(ftype, Container):
            yield from _leaf_uint_paths(value, prefix + (name,))


def _edge_value(leaf: uint) -> uint:
    """An edge value for a uint leaf, guaranteed to differ from ``leaf``.

    Prefer the all-ones maximum for the type's width (the over-range boundary
    the reject-class fuzzer wants to probe); fall back to 0 only when the leaf
    already sits at that maximum, so the mutation always changes the root.
    """
    leaf_type = type(leaf)
    all_ones = (1 << (leaf_type.type_byte_length() * 8)) - 1
    return leaf_type(0 if int(leaf) == all_ones else all_ones)


def mutate_object(obj, rng: random.Random):
    """Return (mutated_copy, MutationOp): pick one uint leaf, set an edge value.

    Deterministic in ``rng``: the same seeded RNG over the same object yields
    identical mutated bytes and an identical ``MutationOp``. Leaves an object
    with no mutable uint leaf untouched (a ``MutationOp((), "")`` sentinel), for
    the byte-level path to cover.
    """
    mutated = obj.copy()
    leaves = list(_leaf_uint_paths(mutated))
    if not leaves:
        return mutated, MutationOp((), "")

    path, current = leaves[rng.randrange(len(leaves))]
    new_value = _edge_value(current)

    target = mutated
    for name in path[:-1]:
        target = getattr(target, name)
    setattr(target, path[-1], new_value)

    return mutated, MutationOp(path, repr(int(new_value)))


def mutate_bytes(data: bytes, rng: random.Random) -> bytes:
    """Flip one byte in place. Length-preserving so SSZ offset tables stay parseable;
    the decode-validity gate at the backend discards mutations that still break decode."""
    if not data:
        return data
    buf = bytearray(data)
    i = rng.randrange(len(buf))
    buf[i] ^= 1 << rng.randrange(8)
    return bytes(buf)
