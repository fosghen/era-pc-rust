use era_engine::dispersion_compare::{compare, ComparisonRequest};
fn case() -> ComparisonRequest {
    serde_json::from_str(include_str!("../examples/dispersion-reference.json")).unwrap()
}
#[test]
fn independent_reference_passes_and_zero_reference_is_explicit() {
    let output = compare(&case()).unwrap();
    assert!(output.passed);
    assert_eq!(output.comparisons, 2);
    assert_eq!(output.failed, 0);
    assert_eq!(output.differences[1].relative_error, None);
    assert!(serde_json::to_string(&output)
        .unwrap()
        .contains("independent_formula"));
}
#[test]
fn wrong_result_is_not_hidden_by_relative_tolerance() {
    let mut input = case();
    input.expected_receptors[0].concentrations_mg_m3[0] = 0.;
    let output = compare(&input).unwrap();
    assert!(!output.passed);
    assert_eq!(output.failed, 1);
    assert!(output.differences[0].absolute_error_mg_m3 > 0.02);
    input = case();
    input.expected_receptors[0].concentrations_mg_m3[0] *= 2.;
    let output = compare(&input).unwrap();
    assert!((output.differences[0].relative_error.unwrap() - 0.5).abs() < 1e-12);
}
#[test]
fn metadata_and_complete_matrix_are_required() {
    let mut input = case();
    input.reference.version.clear();
    assert!(compare(&input).is_err());
    input = case();
    input.expected_receptors.clear();
    assert!(compare(&input).is_err());
    input = case();
    input.expected_receptors[0].id = "wrong".into();
    assert!(compare(&input).is_err());
    input = case();
    input.expected_receptors[0].concentrations_mg_m3.pop();
    assert!(compare(&input).is_err());
    input = case();
    input.concentration_tolerance.absolute = f64::INFINITY;
    assert!(compare(&input).is_err());
}
