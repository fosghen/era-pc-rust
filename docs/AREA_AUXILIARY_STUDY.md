# P1 area-source auxiliary parameters — diagnostic only

This study does not implement area-source fields or enable area imports.
It investigates the source parameters printed in saved Cm tables.

## Evidence and interpretation

The supplied ERA v4 inventory manual, pages 21–24, distinguishes P1 uniform
surface emissions from P2 collections of individual outlets. For P1, outlet
diameter, exit speed and gas-volume flow are zero placeholders, not an ordinary
point-source input with accidentally missing geometry. Area geometry may be
rectangular or polygonal and has separate coordinate conventions.

The supplied MRR-2017 pages 27–28 describe area concentration as the spatial
average of a point-source kernel using total area-source emission. Consequently,
matching auxiliary Cm, Um and Xm is not equivalent to evaluating that integral.
The supplied edition also specifies an integration accuracy requirement; a
simple subdivision with no error analysis must not be treated as sufficient.

## Explicit auxiliary hypothesis

The private probe selected only A1/P1 rows with zero H2, outlet diameter, speed,
flow and temperature placeholders. It checked report-side H, F, terrain and
emission at printed precision. Non-unit terrain remained excluded.

Generated fixtures use an explicitly artificial isothermal point source:
diameter 1 m, speed `1e-6` m/s, consistent volume, and gas temperature equal to
the selected ambient temperature. Height is floored at 2 m. These values select
the existing cold low-speed branch; they are **not recovered physical area
parameters**. Neither original files nor production import/kernel rules change.

For this branch, with terrain coefficient one:

```text
Cm = 0.9 × A × M × F / H^(7/3)
Xm = (5 − F) × 57 × H / 40
Um = 0.5
```

Cm is normalized by the supplied PDK for comparison with the printed table.
Area extent, orientation and polygon vertices do not enter this auxiliary
diagnostic. Applicability of this interpretation to all P1 scenarios is not
established.

## Results

Of 171 previously excluded non-point occurrences, 137 met the probe conditions;
34 were excluded for non-unit terrain. The Rust comparator matched all three
printed parameters in **135/137 occurrences**. Deduplication using source
parameters/identifiers, coordinates and printed expectations yielded **52 unique
numeric cases: 51 matched and one failed**, repeated in two project versions.

Both failures are Xm at the same decimal boundary:

```text
Rust result:       25.650000000000002
Printed result:    25.6
Exact expression:  (5 − 3) × 57 × 9 / 40 = 25.65
```

An independent Decimal calculation of the proposed auxiliary formulas matched
137/137 printed triples; decisions were unchanged at 80 and 120 digits.
Xm uses exact decimal arithmetic here. The fractional power in Cm is a
high-precision numerical calculation, not a formal interval proof.

The exact expression lies on the inclusive printed half-step boundary, while
the f64 calculation lies slightly beyond it. The strict Rust comparator's two
failures remain recorded: no epsilon or data-dependent tolerance was added.
This separates a mathematical boundary agreement from binary arithmetic and
does not recover ERA's rounding implementation.

## Next implementation gates

1. Give the passive/zero-flow auxiliary model an explicit, independently tested
   representation; do not silently substitute fake outlets in normal imports.
2. Resolve rectangle versus polygon geometry and coordinate conventions.
3. Implement spatial integration with an error estimate and explicit
   unconverged/budget-exhausted outcomes.
4. Validate area-only fields before using them to interpret mixed-source fields.
5. Keep terrain and other unsupported branches explicit.

Private probe selection and transformations plus the independent reference have
five synthetic tests. Original data, diagnostic fixtures and comparisons remain
private and are preserved in a separate checkpoint.
