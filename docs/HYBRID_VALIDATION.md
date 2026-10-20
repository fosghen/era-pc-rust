# Independent calculations and ERA compatibility

The development strategy has two separate tracks:

1. Implement and test the documented calculation model independently in Rust.
2. Compare it with saved ERA results, keeping export precision, snapshot
   consistency and any compatibility hypotheses explicit.

A compatibility experiment must not silently change the production model or
turn a skipped case into a validation pass. Synthetic numerical tests, saved
source-parameter comparisons, field diagnostics and optimizer comparisons
provide different kinds of evidence.

## Report-side source consistency guard

`tools/project_source_fixture.py` now reads the source table saved alongside
the results. Before admitting a point-source case it compares H1, H2, diameter,
exit speed, volume, temperature, settling factor, terrain coefficient and
emission against the current source data.

The comparison uses the exact inclusive decimal half-step implied by each
printed value, without an extra epsilon. A blank H2 means zero. Missing or
ambiguous tables/rows, inconsistent source types and differing parameters are
explicit exclusions. Negative-temperature classification happens after this
guard, so a stale warm report cannot masquerade as a cold-source reference.
Non-point sources remain explicitly unsupported, rather than being parsed as
point sources with missing outlet values.

This guard does **not** establish complete snapshot freshness. In particular,
coordinates, receptor height, buildings, background and other spatial settings
require separate checks.

Re-running the latest private corpus retained all 112 stored-volume matches
(98 unique numeric cases) for Cm/PDK, Um and Xm. Fifteen input/report temperature
conflicts are now excluded automatically; 31 consistent negative-temperature
cases remain explicitly unsupported by the production model. No tolerance was
relaxed and no original project was changed.

## First spatial replay diagnostics

Two saved single-source pollutant grids each contain 10,201 points. A
deterministic sample spanning the grid and including the saved maximum selected
33 and 34 points respectively. At each selected point the Rust fixed-wind
calculation was replayed using that point's printed wind direction and speed.
All reported contributing sources were required to be supported, and saved
background/deposition columns were zero.

These are **diagnostics, not field-validation passes**:

- Receptor height was assumed to be 2 m, not independently established.
- Wind and source coordinates are exported with limited precision.
- The saved optimizer was not rerun.
- The sample does not validate all 10,201 points or multiple-source summation.

The report-side source coordinates differ visibly from current input
coordinates. Two separate generated-fixture interventions were evaluated:
use the coordinates printed in the report, or round the input source coordinates
through IEEE-754 binary32. Neither intervention changes the Rust kernel.

| Coordinate interpretation | Grid A maximum relative error | Grid B maximum relative error |
| --- | ---: | ---: |
| Current exported inputs | 1.588471% | 0.0753325% |
| Report-printed coordinates | 0.0216299% | 0.000120351% |
| Input coordinates rounded through binary32 | 0.0107954% | 0.000120351% |

For the binary32 diagnostic, maximum absolute errors were approximately
`6.84e-12` and `9.41e-10` mg/m³ respectively. Relative errors can look large
near very small concentrations. No numerical pass threshold was assigned
after observing these errors.

This supports investigating coordinate representation as a compatibility issue;
it does not prove ERA's internal type or justify automatically converting every
coordinate. Grid B does not distinguish the two interventions numerically.
The remaining errors and the assumed receptor height are unresolved.

## Next gates

1. Confirm coordinate representation and receptor settings against additional
   saved cases; quantify wind/output rounding separately.
2. Establish field comparisons with every contributing source supported, then
   compare the search for adverse wind separately from fixed-wind calculations.
3. Expand negative-temperature, area-source, summation-group and terrain support
   with independent tests and explicit saved-reference coverage.
4. Integrate the supported scope into a Windows CLI workflow with import,
   preflight checks, batch calculation and machine-readable reports.

Existing projects suffice for continued development. Exact equivalence in
unrepresented scenarios remains unproven without additional reference
calculations. Public executables remain deferred until the agreed usable release.

Project fixtures, coordinates and diagnostic requests/results remain private.
The public repository contains the guard, synthetic tests and aggregate findings.

The subsequent [paired replay and full-grid study](FIELD_REPLAY.md) extends the
initial sample to both complete grids and separates wind replay from wind search.
