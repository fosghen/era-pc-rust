# Paired field replay and full-grid diagnostics

## Research tool

`dispersion_replay::replay` evaluates each receptor at the wind with the same
index. It accepts the existing strict `dispersion::Request` format but requires
equal, nonzero receptor and wind counts.

```sh
cargo build --release --locked --example field_replay
target/release/examples/field_replay request.json new-result.json
```

On Windows the example executable has an `.exe` suffix. This is a research
entry point, not a published end-user release.

The ordinary `dispersion` calculation evaluates every supplied wind at every
point. For N points with one individually saved wind per point, paired replay
reduces N×N×S source evaluations to N×S, where S is the source count. Source
parameters are computed once. The replay uses the **same kernel**, validation
and summation order; it is not an independent oracle or a new physical model.

The output records point IDs, corresponding winds, concentrations, source
parameters and the evaluation count. It performs no coordinate conversion,
fits no expected values and assigns no validation pass. Wind search is not
part of this operation.

Limits and error handling:

- At most 20 million source-point evaluations.
- Input file at most 16 MiB.
- Existing model restrictions and source/receptor ID validation remain active.
- An output file must be new; input/previous reports are not overwritten.
- Invalid input or calculation errors produce no output report.

Tests compare replay against the ordinary Cartesian calculation's diagonal,
including multiple sources, ordering, invalid input, evaluation limits, a
5,000-point case and exclusive CLI output creation. CI runs the CLI tests on
Windows, Linux and macOS using synthetic inputs only.

## Full saved grids, 2026-10-20

The previous 67-point diagnostic was extended to **all 20,402 points** in two
saved single-source grids (10,201 points each). Current input rows, saved
source tables, shared grid geometry/order, coordinate orientation, zero
background/deposition columns and selected input hashes were checked.

The supplied ERA-RB manual, sections 8.6–8.7, describes a 2 m ground layer and
a separate elevated-height mode. Both selected controls contain
`+Height Distribution = No (3)`, and shared receptor-grid rows contain only
horizontal geometry. This supports using the 2 m ground-layer calculation,
but is not proof of historical snapshot freshness or a full decoding of the
parenthesized control value.

A building description file is present in one project. Presence of that file,
or absence of one in the other project, does not establish whether buildings
were enabled for the saved calculation. This remains a separate applicability
question; the Rust replay does not model buildings.

| Source coordinate interpretation | Grid A max relative error | Grid B max relative error |
| --- | ---: | ---: |
| Current exported values | 3.06605% | 2.25292% |
| Explicit binary32-coordinate hypothesis | 0.0246944% | 0.000131182% |

For the binary32 hypothesis, maximum absolute errors are approximately
`1.18e-11` and `1.03e-9` mg/m³. Very small expected concentrations account for
the larger relative errors in grid A. Only 7,874 and 971 values respectively
fall within the exact half-step of the printed concentration. These counts
describe printed precision; **they are not field-validation passes**.

Coordinate conversion affects generated diagnostic requests only, not the
production kernel or original project files. The evidence supports continued
investigation of export/internal coordinate representation, not a universal
binary32 compatibility rule.

Each measured 10,201-point replay took about 0.032 s locally, including
subprocess startup and request/result JSON I/O. Fixture extraction, hashing and
Python analysis are excluded. This is not a benchmark against ERA or a promise
for other machines.

## Rounding probes versus wind optimization

For seven selected points per grid, a separate diagnostic sampled the center
and edges of the printed wind rounding cells: direction offsets ±0.5 degrees
and speed offsets ±0.005 m/s, clipped to supported wind bounds. Saved
concentrations lay inside the sampled concentration range for 6/7 and 5/7
points. Sample extrema are not continuous bounds; these counts prove neither
equivalence nor a general rounding explanation.

The independent wind-search algorithm was then run at those 14 points using
the same diagnostic source coordinates. Initially, seven grid-A points and
two grid-B points met `grid_stable`; the other five reported
`refinement_limit`. Re-running those five with a 4-million-evaluation budget
each and finer steps brought them to `grid_stable`. Each used 3,952,783 source
evaluations; the five-point rerun took about 0.60 s locally.

The best-found concentrations exceed the saved maxima by up to approximately
0.139% and 0.291% on these selections. This distinguishes fixed-wind replay
from optimization. It does not establish that ERA is wrong: wind resolution,
search strategy, input representation and calculation settings can differ.
`grid_stable` is a grid-refinement criterion, not proof of the continuous global
maximum.

## Remaining evidence gaps

- Establish building-mode and historical input consistency.
- Isolate remaining numerical/printed-wind effects before defining a field
  acceptance tolerance.
- Extend beyond two single-source grids to fully supported multi-source fields.
- Continue independent implementations and tests for cold gas, area sources,
  summation groups and terrain; no unsupported behavior is silently enabled.

Original grids and all generated requests/results remain private. Their hashes
and code snapshots are recorded in the research checkpoint.
