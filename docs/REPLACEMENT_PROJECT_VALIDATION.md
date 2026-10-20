# Replacement project batch — 2026-10-20

This is a source-parameter comparison, not certification or full project
equivalence. Original projects and extracted fixtures remain private.

## Coverage

The replacement input contains seven collections, 19 project/version directories,
255 saved Cm tables and 266 calculation controls. Two directories have no result
folders. One version has saved reports without the matching input/control set;
inputs from another version were not substituted.

Every inspected control uses automatic wind-speed and wind-direction search.
There is no fixed-wind reference calculation in this batch.

| Input profile | Compared source/pollutant pairs | Passed all three parameters | Failed |
| --- | ---: | ---: | ---: |
| Printed speed | 29 | 5 | 24 |
| Stored volume, consistent with printed-speed rounding | 5 | 5 | 0 |

The three parameters are Cm/PDK, Um and Xm. These two profiles overlap and must
not be added together as independent validations. Neither profile contained
identical numeric-case repetitions under the batch tool's signature.
Passing five eligible pairs does not validate the other projects.

Stored-volume exclusions, counted as occurrences rather than unique sources:

| Reason | Occurrences |
| --- | ---: |
| Gas colder than ambient | 148 |
| Non-point source | 244 |
| Summation group | 59 |
| Terrain coefficient other than one | 14 |
| Missing or oversized matching text file | 13 |
| Volume-derived speed inconsistent with printed-speed rounding | 24 |

The counting units include source/pollutant rows and report-level exclusions;
versions repeat some inputs. Do not sum these into a unique-source count.

## Import and comparison changes

Source inputs now accept bounded scientific notation, including small emissions.
Previously these valid source rows were rejected by the fixed-decimal parser.
Saved expected results still require fixed-decimal strings: their printed
precision determines the tolerance, and scientific notation is not accepted
there. Nonfinite, overflowing and underflowing source values are rejected.

The new batch runner distinguishes comparisons, no eligible cases, absent result
folders and errors. It checks selected input hashes after extraction and after
comparison, validates comparator decisions and counts, and records duplicate
numeric cases separately. All checks on selected files passed in this run.
Hashes establish which files were used, not the authenticity or freshness of
saved ERA results.

Example, from the repository root:

```sh
cargo build --release --example archive_source_compare
python3 tools/project_batch_compare.py \
  --roots /private/collection-a /private/collection-b \
  --comparator target/release/examples/archive_source_compare \
  --output /private/new-batch-results
```

The output directory must be new and outside the original collections. Generated
fixtures contain project data and must not be published. Exit status 1 means at
least one comparison failed or a job was not validated; it is expected for a
partially supported batch. Only the repository's own comparator is executed.

## Separate cold-gas hypothesis — not accepted validation

A private diagnostic copied eligible cold-source rows and replaced gas
temperature with ambient temperature **only in generated fixtures**, leaving
all original files untouched. Other eligibility checks, including volume/speed
consistency, remained enabled. The production importer and calculation kernel
still reject negative temperature differences.

Across four selected project versions, this intervention produced:

- 80 of 81 source/pollutant pairs matching all three printed parameters;
- 242 of 243 individual metrics matching;
- 34 configurations of A, ambient temperature, H, D, speed, temperature and F.

The single mismatch is Xm: the calculation produces binary floating-point
`82.65`, while the report prints `82.6`. The exact decimal expression for that
branch is `0.5 * 5.7 * 29 = 82.65`, on the rounding boundary. The binary result
lies just beyond the exact upper tolerance boundary. It remains a failure:
no extra epsilon or relaxed pass criterion was introduced. This is a boundary
rounding discrepancy, not proof of the original formatter's behavior.

This is evidence for a candidate treatment of negative temperature differences,
not recovery of the full rule. The supplied methodology pages describe the
ordinary cold branch using nonnegative temperature differences and separately
describe a restricted near-zero negative case. They do not justify applying
the diagnostic intervention to every negative difference.

The inspected project variants also change height or volume and, for some rows,
emissions together with temperature. They are not controlled temperature-only
experiments. Further validation needs such paired calculations, preferably
including fixed-wind point concentrations, before changing the production guard.

## Verification and remaining work

The Python tool suite passes 477 tests; the separate private hypothesis probe
passes three synthetic safety/selection tests. The checkpoint manifest records
the exact tool, fixture and report hashes. Private checkpoint snapshots include
the local kernel/dependency state used for comparison, including pre-existing
uncommitted changes; those changes are not part of this batch's commit.

Remaining gaps include the negative-temperature rule, area sources, summation
groups, non-unit terrain, inconsistent flow inputs and full spatial/wind-search
comparisons. No original executable was launched for this batch.
