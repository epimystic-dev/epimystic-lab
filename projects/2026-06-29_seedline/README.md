# seedline

One opinionated function — `seed_all(n)` — that seeds every RNG that matters
across Python, NumPy, and PyTorch from a single call. A matching context
manager — `seeded(n)` — does the same and **restores prior state on exit**,
so a deterministic block leaves no global side effects behind. Pure stdlib
core; NumPy and PyTorch integrations are optional and detected at runtime.

```python
from seedline import seed_all, seeded

# top-of-program lockdown
seed_all(42)

# scope-limited determinism — exits restore the prior RNG state
with seeded(0):
    sample = my_model.sample()
    # ... etc.
# RNG state outside the block is untouched
```

## Why this exists

Every project that uses randomness invents its own `seed_everything`. They
all look almost the same and they almost-all have at least one bug:

- forgetting `numpy.random.seed` (so `np.random.rand()` is non-deterministic),
- forgetting `torch.cuda.manual_seed_all` (so multi-GPU runs diverge),
- pretending to lock `PYTHONHASHSEED` *after* interpreter start (impossible),
- accepting `True` as a seed (because `bool` is an `int`) and silently using
  `seed=1` everywhere,
- mutating global state with no way to undo, breaking unrelated tests in the
  same pytest session.

`seedline` is small enough to read in one sitting and tested for each of the
above that is testable without GPU hardware (the CUDA path is exercised on
machines that have a CUDA device; the CI matrix here is CPU-only).

## Install

```
pip install -e .
```

No required runtime dependencies. NumPy and PyTorch are sniffed via
`__import__` at call time; if absent, the corresponding work is skipped.

## API

### `seed_all(seed: int) -> SeedSnapshot`

Seeds `random`, `numpy.random` (if present), `torch.manual_seed` and
`torch.cuda.manual_seed_all` (if present). Returns a `SeedSnapshot` of the
state *before* seeding so you can `restore()` it later.

Validates `seed` is a non-bool integer in `[0, 2**32)` — the intersection of
what NumPy's legacy `RandomState` and `torch.manual_seed` accept on every
platform.

### `seeded(seed: int)` — context manager

```python
with seeded(42) as prior_snapshot:
    ...  # deterministic block
# prior state restored, even if the body raised
```

### `snapshot() / restore(snap)`

Capture and restore RNG states explicitly. The stdlib `random` state is an
exact round-trip; for the other backends, this round-trip is whatever the
backend itself provides (see *Limits* below).

### `detect() -> dict[str, str]`

Reports which backends were found, e.g.
`{"python": "present", "numpy": "present (2.1.3)", "torch": "absent", ...}`.
Useful in a test-suite banner.

### Optional pytest fixture

```python
# conftest.py
pytest_plugins = ["seedline.pytest_plugin"]

# test_x.py
def test_thing(seeded_run):
    with seeded_run(42):
        ...
```

## Scope and honest limits

- **`PYTHONHASHSEED` cannot be set after interpreter start.** `seedline`
  reads it for the snapshot but never claims to enforce it; if you need it,
  set it in your launcher (`PYTHONHASHSEED=0 python -m pytest`).
- **PyTorch determinism switch is *not* toggled.** Enabling
  `torch.use_deterministic_algorithms(True)` has performance and operator-
  coverage implications, and some ops will then raise. We deliberately
  leave that switch to you. Recommended opt-in:
  ```python
  import torch
  torch.use_deterministic_algorithms(True, warn_only=False)
  torch.backends.cudnn.deterministic = True
  torch.backends.cudnn.benchmark = False
  ```
- **NumPy `Generator` API isn't global.** `np.random.default_rng(seed)`
  returns a *fresh* generator and is unaffected by anything global. If your
  code passes a `Generator` instance around, seed it yourself; `seedline`
  only seeds the legacy `RandomState` (which is what `np.random.seed`
  controls and what most code still uses).
- **Multi-process / DataLoader workers.** If you spawn workers, each worker
  has its own RNG state and must be seeded inside its setup hook. `seedline`
  does not paper over this.
- **`os.urandom`, `secrets`, and OS-backed RNGs are NOT seedable** and
  `seedline` does not pretend otherwise.

## Tests

```
python -m unittest discover -s tests
```

24 tests; NumPy tests are skipped if NumPy isn't installed, PyTorch tests
are skipped if PyTorch isn't installed.

## License

MIT. See `LICENSE`.

## Provenance

Built by a human–machine hybrid intelligence working under a published
governance + clean-room build protocol. Clean-room: not derived from any
existing seed-everything helper.
