# consensus-diff wire protocol

This protocol is compatible with the pyspec conformance servers in the wild.
consensus-diff reimplements it from documented behavior rather than from the
original LGPL sources; see *pyspec-harness-behavior.md* (external reference,
§Provenance) for the full behavioral record that grounded this specification.

A *backend* is any long-lived subprocess that speaks this protocol.  The
harness drives N ≥ 2 backends concurrently over the same consensus-spec-tests
corpus, collects a verdict from each per case, and flags any disagreement.
The harness never judges against an expected-output file itself.

---

## 1. Transport

- **Channel:** stdin / stdout pipes between the harness and the backend.
  Framing is line-oriented text (UTF-8).
- **Requests** are single **tab-separated** lines terminated by `\n`, one per
  test case; the harness flushes after writing each line.
- **Responses** are a single line per request (§4); a backend MUST flush after
  each response.
- **stderr** is free-form logging.  The harness captures it to a per-backend
  log file and MUST NOT parse it.
- **Startup noise:** any stdout line whose first tab-field is neither `pass`
  nor `fail` is treated as pre-protocol output (build noise, version banners,
  loading messages) and silently discarded.  The harness loops until a
  protocol line arrives.

---

## 2. Invocation

```
<cmd> <fork> <preset>
```

`<cmd>` is the backend-specific executable (and any fixed arguments).
`<fork>` is the consensus fork name (e.g. `fulu`, `gloas`, `heze`).
`<preset>` is the spec-tests preset, either `minimal` or `mainnet`.

A backend MUST exit with status **2** if it does not support the requested
(fork, preset) pair.

---

## 3. Request lines

Three request shapes exist, selected by the runner name in field 1:

| runner(s) | fields | section |
|---|---|---|
| `sanity`, `finality`, `random`, `epoch_processing`, `operations`, `rewards`, `genesis`, `fork`, `transition` | 10 | §3.1 |
| `fork_choice` | 8 | §3.2 |
| `ssz_static` | 4 | §3.3 |

Fields within a line are separated by `\t`; the line ends with `\n`.

### 3.1 Generic 10-field line

Used by the nine runners listed above.

| # | field | encoding |
|---|---|---|
| 1 | runner | directory name, e.g. `operations` |
| 2 | handler | directory name, e.g. `attestation` |
| 3 | pre-state path | absolute path to decompressed `pre.ssz`; **`-`** if absent |
| 4 | post-state path | absolute path to decompressed `post.ssz`; **`-`** if absent (invalid vector) |
| 5 | bls_setting | integer as string; default `1` when absent from `meta.yaml` |
| 6 | blocks_count | integer as string; count of `blocks_*` files in the case directory |
| 7 | fork_epoch | integer as string; **`-`** if absent from `meta.yaml` |
| 8 | inputs | comma-joined absolute paths of assembled input files (see below); **empty string** (not `-`) when there are no input files |
| 9 | fork_block | integer as string; **`-`** if absent from `meta.yaml` |
| 10 | execution_valid | `1` or `0`; `0` only for `operations`/`execution_payload` when `execution.yaml` sets `execution_valid: false`; `1` otherwise |

**Two distinct absent markers coexist:** `-` for fields 3, 4, 7, and 9; the
empty string for field 8.  A backend MUST handle both.

**Field 8 — input assembly order:**

Inputs are assembled from decompressed files and appended in the following
order.  Only rules that apply to the active runner contribute entries.

1. **`blocks_N` files** (all nine runners) — all decompressed `blocks_N.ssz`
   files, sorted **numerically by N** (not lexicographically; `blocks_10`
   follows `blocks_2`).

2. **Operations operand** (`operations` runner only) — the single decompressed
   operand file whose stem is not `pre`, not `post`, and does not start with
   `blocks_` (e.g. `attestation.ssz`).

3. **Slots count blob** (`sanity`/`slots` handler only) — a binary file
   containing the slot count encoded as **minimal-length big-endian bytes,
   minimum one byte** (slot count 0 → the single byte `0x00`).  A backend
   decodes this input big-endian to obtain the slot count.  This is the only
   non-SSZ binary input in the protocol.

4. **Rewards deltas** (`rewards` runner only) — the four expected-deltas blobs
   appended in the fixed order: `source_deltas`, `target_deltas`,
   `head_deltas`, `inactivity_penalty_deltas`.  Any file absent in the case
   directory is skipped (not represented by a placeholder).

**`genesis` runner note:** no genesis-specific input assembly exists.  A
`genesis` case uses the generic line, and its non-`blocks_*` snappy files
(e.g. deposits, genesis state) do not appear in field 8.  The backend is
responsible for classifying and locating these files independently.

### 3.2 fork_choice 8-field line and script grammar

**Request line:**

| # | field | value |
|---|---|---|
| 1 | runner | `fork_choice` |
| 2 | handler | directory name, e.g. `ex_ante` |
| 3 | anchor-state path | absolute path to decompressed `anchor_state.ssz` |
| 4 | (fixed placeholder) | `-` |
| 5 | (fixed placeholder) | `1` |
| 6 | (fixed placeholder) | `0` |
| 7 | (fixed placeholder) | `-` |
| 8 | inputs | `<anchor_block_path>,<script_path>` — two comma-joined absolute paths |

Field 8 is always a comma-joined pair: the decompressed `anchor_block.ssz`
path, then the path of the generated script file.  Fields 4–7 are the literal
placeholder values shown above.

**Script file format:**

The script file is a sequence of space-separated lines joined by `\n` with
**no trailing newline**.  Each entry in `steps.yaml` produces one or more
lines as follows.

Non-`checks` step entries each produce **one line**:

| step key | emitted line |
|---|---|
| `tick` | `tick <int>` |
| `block` | `block <path> <1\|0> <cols>` — `<1\|0>` is the step's `valid` key (default true → `1` when absent); `<cols>` is a comma-joined list of decompressed DataColumnSidecar paths for the step's `columns` list, or the literal `-` when the list is absent or empty |
| `attestation` | `attestation <path> <1\|0>` |
| `attester_slashing` | `attester_slashing <path> <1\|0>` |
| `execution_payload` | `execution_payload <path> <1\|0>` |
| `payload_attestation_message` | `payload_attestation_message <path> <1\|0>` |
| any unrecognized key | `unsupported <keys>` — the step's keys minus `valid` and `columns`, sorted lexicographically, joined with `/`; exactly `unsupported unknown-step` when that remaining set is empty |

`checks` entries expand to **one line per sibling key**:

| checks key | emitted line(s) |
|---|---|
| `get_proposer_head` | `get_proposer_head <root>` |
| `should_override_forkchoice_update` | `unsupported should_override_forkchoice_update` — deliberately unimplemented; demotes the case to the `todo` bucket |
| `head` | `head <root> <slot>`; additionally `head_payload_status <int>` as a separate line when the `payload_status` sub-key is present |
| `payload_timeliness_vote` | `payload_timeliness_vote <block_root> <votes>` — `<votes>` is a comma-joined sequence of `t` (true) / `f` (false) / `n` (null or any other value) |
| `payload_data_availability_vote` | `payload_data_availability_vote <block_root> <votes>` (same vote encoding) |
| `justified_checkpoint` | `justified <epoch> <root>` |
| `finalized_checkpoint` | `finalized <epoch> <root>` |
| `proposer_boost_root` | `boost <root>` |
| `time` | `time <int>` |
| `genesis_time` | `genesis_time <int>` |
| unknown top-level key, or unrecognized sub-key of a known nested check | `unsupported <names>` — unknown top-level keys plus `parent.subkey` forms for unmodeled sub-keys of known nested checks, all sorted and joined with `/` |

**Design intent:** any unmodeled key or sub-key MUST surface as an explicit
`unsupported` line so the case reports a visible coverage gap rather than
passing with the check silently dropped.

**Path whitespace constraint:** script lines are space-delimited with embedded
absolute paths; a path containing whitespace mis-splits the line.  The harness
MUST ensure generated paths are whitespace-free; a backend that encounters a
space in a position it expects to be part of a path MAY treat the line as
malformed.

### 3.3 ssz_static 4-field line

| # | field | encoding |
|---|---|---|
| 1 | runner | `ssz_static` |
| 2 | handler | container type name, e.g. `BeaconBlock` |
| 3 | serialized path | absolute path to decompressed `serialized.ssz` |
| 4 | expected root | hex root string from `roots.yaml` |

A backend MUST perform both of the following checks:

1. Deserialize the bytes at field 3 as the container type named in field 2,
   using the active fork's schema; compute its hash-tree-root and compare
   against field 4.
2. Re-serialize the deserialized value and compare the output byte-for-byte
   against the original input bytes (round-trip check).

A mismatch on either check MUST be reported as a `fail`.

---

## 4. Response

```
<verdict>\t<bucket>\t<detail>
```

| field | constraints |
|---|---|
| verdict | exactly `pass` or `fail` |
| bucket | one of the vocabulary in §5; if absent (the line has only the verdict token), the harness treats it as `?` |
| detail | free-form string; MUST NOT contain tab or newline characters; may be empty |

**Default for missing fields:** a line with only a verdict token maps to
bucket `?` and empty detail.  A line with verdict and bucket but no third
field maps to empty detail.

**`bug` outranks the verdict token:** a response carrying bucket `bug` is
treated as a hard failure regardless of whether the verdict field reads `pass`
or `fail`.

---

## 5. Bucket vocabulary

Working pin — reconciled against observed backend emissions at the M1 smoke;
unlisted buckets are normalized to `other:<string>` by the harness and never
silently compare equal.

| bucket | typical verdict | semantics |
|---|---|---|
| `ok` | `pass` | Valid vector: the backend's computed post-state or root matched. |
| `reject` | `pass` | Invalid vector: the backend's spec implementation faithfully rejected it (honest-verdict pass). |
| `mismatch` | `fail` | Valid vector: result did not match the expected post-state or root. |
| `accept-invalid` | `fail` | Invalid vector: the backend accepted it when the spec requires rejection. |
| `reject-valid` | `fail` | Valid vector: the backend rejected it when the spec requires acceptance. |
| `todo` | `fail` | Unimplemented code path — a visible, non-scoring coverage gap; becomes `pass` automatically once the stub is filled, with no test-side change required. |
| `skip` | `fail` | Deliberately unmodeled — the case is excluded from the diff comparison and does not inflate the fail count. |
| `bug` | either | Harness-contract violation: crash, out-of-bounds, missing-key, or malformed response on well-formed input.  Outranks every other outcome including a `pass` verdict; scored as a hard failure unconditionally. |
| `?` | — | Default when the bucket field is absent.  A `fail\t?\t...` response is a hard failure. |

**Honest-verdict model:** a `pass` means either a valid vector's computed
output matched or an invalid vector was genuinely rejected by the backend's
spec logic.  The classification among `ok`, `reject`, `mismatch`,
`accept-invalid`, and `reject-valid` is made server-side; the harness maps
buckets to outcomes and flags cross-backend disagreements.

---

## 6. Backend lifecycle

- **Warm process:** a backend is a long-lived process shared across all cases
  for a given (fork, preset) session.  The harness MAY kill and respawn a
  backend at any time.
- **Shutdown:** when the harness closes the backend's stdin (EOF), the backend
  SHOULD exit cleanly.  The harness allows **30 seconds** for the process to
  exit, then sends SIGKILL.
- **Respawn and retry:** on detecting backend death (broken pipe, closed
  stdout, OS pipe error), the harness respawns the backend and retries the
  in-flight request **at most once**.  A second failure scores the case as
  `fail\tbug\tserver died; re-spawned and retried, case still failed`.
  Rationale: a transient first-request hiccup under parallel workers must not
  surface as a spurious failure.
- **Per-case timeout:** the harness enforces a default **300-second** deadline
  per case.  A backend that does not respond within this window is killed; the
  case is scored as an infrastructure failure, not attributed to the backend's
  spec logic.
- **Fixed (fork, preset) per session:** a backend is started with exactly one
  fork and one preset and MUST NOT receive cases for any other (fork, preset)
  pair during the same session.

---

## 7. Reserved verbs

The runner names in §3 are the recognized first-field values.  Two additional
first-field values are reserved for future milestones:

| verb | milestone | semantics |
|---|---|---|
| `compute` | M2 | TBD — new request type, not a runner name |
| `generate` | M3 | TBD — new request type, not a runner name |

A backend that receives a first-field value it does not recognize MUST respond:

```
fail\ttodo\tunsupported verb <name>
```

where `<name>` is the unrecognized first-field string verbatim.  This ensures
older backends degrade into a visible, non-scoring coverage gap rather than
producing noise in the diff.

---

## Provenance

Wire-format facts in this document are derived exclusively from
`pyspec-harness-behavior.md` (behavioral record, 2026-07-03,
`feat/heze-focil-alpha11`@`573e830`, located in the EPF research repository).
No LGPL source was read in producing this document.
