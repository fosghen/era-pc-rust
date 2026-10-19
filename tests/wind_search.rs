use era_engine::{
    dispersion::{calculate, Wind},
    wind_search::{search, SearchRequest},
};

fn case() -> SearchRequest {
    let mut r: SearchRequest =
        serde_json::from_str(include_str!("../examples/dispersion-search.json")).unwrap();
    r.calculation.receptors.truncate(1);
    r.search.initial_directions = 12;
    r.search.initial_speed_intervals = 8;
    r.search.max_refinements = 3;
    r.search.direction_tolerance_degrees = 4.;
    r.search.speed_tolerance_m_s = 0.2;
    r
}
#[test]
fn single_source_peak_seed_and_grid_stability() {
    let mut input = case();
    let p = input.calculation.sources[0].parameters(200., 20.).unwrap();
    input.calculation.receptors[0].y_m = p.xm_m;
    let output = search(&input).unwrap();
    let point = &output.receptors[0];
    assert!((point.best_found_mg_m3 - p.cm_mg_m3).abs() < 1e-12);
    assert_eq!(point.wind.from_degrees, 180.);
    assert_eq!(point.status, "grid_stable");
    assert!(point.history.len() >= 3);
    assert!(point
        .history
        .windows(2)
        .all(|w| w[1].best_concentration_mg_m3 >= w[0].best_concentration_mg_m3));
    assert!(point.source_evaluations <= input.search.max_source_evaluations_per_receptor);
}
#[test]
fn best_wind_replays_through_fixed_wind_kernel() {
    let mut input = case();
    let mut source = input.calculation.sources[0].clone();
    source.id = "second".into();
    source.x_m = 150.;
    source.height_m = 12.;
    input.calculation.sources.push(source);
    input.calculation.winds = vec![Wind {
        from_degrees: 210.123,
        speed_m_s: 1.234,
    }];
    let seeded = calculate(&input.calculation).unwrap();
    let found = search(&input).unwrap();
    let point = &found.receptors[0];
    assert!(point.best_found_mg_m3 >= seeded.receptors[0].sampled_max_mg_m3);
    input.calculation.winds = vec![point.wind];
    let replay = calculate(&input.calculation).unwrap();
    assert_eq!(
        point.best_found_mg_m3,
        replay.receptors[0].sampled_max_mg_m3
    );
    assert_eq!(
        point.source_contributions_mg_m3,
        replay.receptors[0].contributions_at_worst_mg_m3
    );
}
#[test]
fn agrees_with_independent_dense_fixed_wind_sweep() {
    let mut input = case();
    input.calculation.receptors[0].x_m = 117.;
    let mut second = input.calculation.sources[0].clone();
    second.id = "second".into();
    second.x_m = 200.;
    second.emission_g_s = 0.7;
    input.calculation.sources.push(second);
    input.search.initial_directions = 36;
    input.search.initial_speed_intervals = 20;
    input.search.max_refinements = 4;
    input.search.direction_tolerance_degrees = 1.;
    input.search.speed_tolerance_m_s = 0.05;
    input.search.max_source_evaluations_per_receptor = 1_000_000;
    let found = search(&input).unwrap();
    input.calculation.winds = (0..720)
        .flat_map(|i| {
            (0..=190).map(move |j| Wind {
                from_degrees: i as f64 * 0.5,
                speed_m_s: 0.5 + j as f64 * 0.05,
            })
        })
        .collect();
    let dense = calculate(&input.calculation).unwrap().receptors[0].sampled_max_mg_m3;
    assert!(
        found.receptors[0].best_found_mg_m3 >= dense * 0.999,
        "search {}, dense {}",
        found.receptors[0].best_found_mg_m3,
        dense
    );
}
#[test]
fn periodic_direction_and_zero_emission_are_deterministic() {
    let mut input = case();
    let p = input.calculation.sources[0].parameters(200., 20.).unwrap();
    input.calculation.receptors[0].y_m = -p.xm_m;
    assert_eq!(search(&input).unwrap().receptors[0].wind.from_degrees, 0.);
    input.calculation.sources[0].emission_g_s = 0.;
    let a = search(&input).unwrap();
    let b = search(&input).unwrap();
    assert_eq!(a.receptors[0].best_found_mg_m3, 0.);
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}
#[test]
fn incomplete_search_is_explicit_and_bad_settings_fail() {
    let mut input = case();
    input.search.max_source_evaluations_per_receptor = 500;
    let output = search(&input).unwrap();
    assert_eq!(output.receptors[0].status, "evaluation_budget");
    assert!(output.receptors[0].source_evaluations <= 500);
    input.search.max_source_evaluations_per_receptor = 1;
    assert!(search(&input).is_err());
    input = case();
    input.search.max_refinements = 0;
    assert_eq!(
        search(&input).unwrap().receptors[0].status,
        "refinement_limit"
    );
    input.search.initial_directions = 0;
    assert!(search(&input).is_err());
    input = case();
    input.search.concentration_relative_tolerance = f64::NAN;
    assert!(search(&input).is_err());
    input = case();
    input.calculation.winds.push(Wind {
        from_degrees: 360.1,
        speed_m_s: 1.,
    });
    assert!(search(&input).is_err());
}
