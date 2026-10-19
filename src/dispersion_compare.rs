//! Fixed-wind differential checks. Reference provenance is declared by the
//! fixture author; this command cannot authenticate an ERA export.
use crate::{
    dispersion::{calculate, Request},
    Result,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    IndependentFormula,
    EraExport,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub kind: ReferenceKind,
    pub program: String,
    pub version: String,
    pub case_id: String,
    /// Export file identifier/hash, or independently evaluated formula provenance.
    pub provenance: String,
    /// Calculation mode, rounding/export precision, terrain/background etc.
    pub settings: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tolerance {
    pub absolute: f64,
    pub relative: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPoint {
    pub id: String,
    pub concentrations_mg_m3: Vec<f64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonRequest {
    pub calculation: Request,
    pub reference: Reference,
    pub concentration_tolerance: Tolerance,
    /// Full matrix: same receptor order and wind order as the calculation.
    pub expected_receptors: Vec<ExpectedPoint>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Difference {
    pub receptor_id: String,
    pub wind_index: usize,
    pub expected_mg_m3: f64,
    pub actual_mg_m3: f64,
    pub absolute_error_mg_m3: f64,
    /// None when reference is zero, including exact zero/zero matches.
    pub relative_error: Option<f64>,
    pub allowed_error_mg_m3: f64,
    pub passed: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct ComparisonResult {
    pub reference: Reference,
    pub tolerance: Tolerance,
    pub passed: bool,
    pub comparisons: usize,
    pub failed: usize,
    pub differences: Vec<Difference>,
    pub warnings: Vec<String>,
}
pub fn compare(input: &ComparisonRequest) -> Result<ComparisonResult> {
    let t = &input.concentration_tolerance;
    if !t.absolute.is_finite()
        || t.absolute < 0.
        || !t.relative.is_finite()
        || !(0. ..=1.).contains(&t.relative)
    {
        return Err("Tolerances must be finite and nonnegative; relative must be <=1".into());
    }
    for text in [
        &input.reference.program,
        &input.reference.version,
        &input.reference.case_id,
        &input.reference.provenance,
        &input.reference.settings,
    ] {
        if text.trim().is_empty() {
            return Err("Reference provenance fields must not be empty".into());
        }
    }
    if input.expected_receptors.len() != input.calculation.receptors.len() {
        return Err("Reference must cover every receptor".into());
    }
    for (expected, point) in input
        .expected_receptors
        .iter()
        .zip(&input.calculation.receptors)
    {
        if expected.id != point.id
            || expected.concentrations_mg_m3.len() != input.calculation.winds.len()
        {
            return Err("Reference must match receptor IDs/order and cover every wind".into());
        }
        if expected
            .concentrations_mg_m3
            .iter()
            .any(|c| !c.is_finite() || *c < 0.)
        {
            return Err("Reference concentrations must be finite and nonnegative".into());
        }
    }
    let result = calculate(&input.calculation)?;
    let mut differences = Vec::new();
    for (point, expected) in result.receptors.iter().zip(&input.expected_receptors) {
        for (index, (&actual, &reference)) in point
            .concentrations_mg_m3
            .iter()
            .zip(&expected.concentrations_mg_m3)
            .enumerate()
        {
            let absolute = (actual - reference).abs();
            let allowed = t.absolute + t.relative * reference.abs();
            if !allowed.is_finite() {
                return Err("Comparison tolerance overflow".into());
            }
            let relative = if reference == 0. {
                None
            } else {
                Some(absolute / reference.abs())
            };
            // Overflow is not silently serialized as a misleading JSON null.
            if relative.is_some_and(|v| !v.is_finite()) {
                return Err("Relative error overflow".into());
            }
            differences.push(Difference {
                receptor_id: point.id.clone(),
                wind_index: index,
                expected_mg_m3: reference,
                actual_mg_m3: actual,
                absolute_error_mg_m3: absolute,
                relative_error: relative,
                allowed_error_mg_m3: allowed,
                passed: absolute <= allowed,
            });
        }
    }
    let failed = differences.iter().filter(|d| !d.passed).count();
    Ok(ComparisonResult { reference: input.reference.clone(), tolerance: t.clone(), passed: failed == 0,
        comparisons: differences.len(), failed, differences,
        warnings: vec![
            "Reference provenance is supplied by the fixture author, not authenticated by this tool.".into(),
            "A passing case validates only its fixed-wind concentration matrix, not all ERA functionality or wind optimization.".into(),
        ] })
}
