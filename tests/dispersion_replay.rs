use era_engine::{
    dispersion::{calculate, Request, Wind},
    dispersion_replay::replay,
};

fn sample() -> Request {
    let mut r: Request = serde_json::from_str(include_str!("../examples/dispersion.json")).unwrap();
    r.receptors.truncate(2);
    r.winds = vec![
        Wind {
            from_degrees: 180.,
            speed_m_s: 2.,
        },
        Wind {
            from_degrees: 270.,
            speed_m_s: 3.,
        },
    ];
    r
}

#[test]
fn paired_replay_matches_cartesian_diagonal_with_multiple_sources() {
    let mut r = sample();
    let mut second = r.sources[0].clone();
    second.id = "second".into();
    second.x_m += 13.;
    second.emission_g_s *= 2.;
    r.sources.push(second);
    let expected = calculate(&r).unwrap();
    let actual = replay(&r).unwrap();
    assert_eq!(actual.source_evaluations, 4);
    for (i, point) in actual.points.iter().enumerate() {
        assert_eq!(point.id, r.receptors[i].id);
        assert_eq!(point.wind.from_degrees, r.winds[i].from_degrees);
        assert_eq!(
            point.concentration_mg_m3,
            expected.receptors[i].concentrations_mg_m3[i]
        );
    }
}

#[test]
fn one_wind_per_point_and_nonempty_inputs_required() {
    let mut r = sample();
    r.winds.pop();
    assert!(replay(&r).unwrap_err().contains("one wind per receptor"));
    r.winds.clear();
    r.receptors.clear();
    assert!(replay(&r).is_err());
}

#[test]
fn full_kernel_validation_is_preserved() {
    for mutation in 0..7 {
        let mut r = sample();
        match mutation {
            0 => r.receptors[1].height_m = 3.,
            1 => r.receptors[1].id = r.receptors[0].id.clone(),
            2 => r.winds[1].speed_m_s = 0.49,
            3 => r.winds[1].from_degrees = f64::NAN,
            4 => r.sources[0].gas_temperature_c = r.air_temperature_c - 1.,
            5 => r.receptors[1].x_m = 1e9,
            _ => r.sources[0].emission_g_s = -1.,
        }
        assert!(replay(&r).is_err(), "mutation {mutation}");
    }
}

#[test]
fn large_paired_request_avoids_cartesian_budget_and_preserves_order() {
    let mut r = sample();
    let point = r.receptors[0].clone();
    r.receptors = (0..5000)
        .map(|i| {
            let mut p = point.clone();
            p.id = format!("p-{i}");
            p
        })
        .collect();
    r.winds = vec![r.winds[0]; 5000];
    assert!(calculate(&r).is_err());
    let result = replay(&r).unwrap();
    assert_eq!(result.source_evaluations, 5000);
    assert_eq!(result.points[4999].id, "p-4999");
    assert_eq!(
        result.points[4999].concentration_mg_m3,
        result.points[0].concentration_mg_m3
    );
}

#[test]
fn paired_evaluation_budget_remains_bounded() {
    let mut r = sample();
    r.sources = vec![r.sources[0].clone(); 1000];
    r.receptors = vec![r.receptors[0].clone(); 20001];
    r.winds = vec![r.winds[0]; 20001];
    assert!(replay(&r).unwrap_err().contains("20 million"));
}
