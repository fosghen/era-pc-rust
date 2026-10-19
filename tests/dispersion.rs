use era_engine::dispersion::{calculate, Outlet, Request, Wind};

fn sample() -> Request {
    serde_json::from_str(include_str!("../examples/dispersion.json")).unwrap()
}
fn close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() <= 2e-12 * expected.abs().max(1e-8),
        "actual={actual:.17e}, expected={expected:.17e}"
    );
}

#[test]
fn warm_reference_from_independent_decimal_evaluation() {
    // Decimal, 60 digits, equations (3)-(10), (15)-(18). NOT ERA output.
    let r = sample();
    let p = r.sources[0].parameters(200., 20.).unwrap();
    assert_eq!(p.regime, "warm_3");
    close(p.effective_volume_m3_s, 7.853981633974483);
    close(p.f.unwrap(), 1.111111111111111);
    close(p.v_m, 1.9300544685992504);
    close(p.v_m_prime, 0.4333333333333333);
    close(p.f_e, 65.0962962962963);
    close(p.m.unwrap(), 0.8868689776422292);
    close(p.n.unwrap(), 1.000742635819882);
    close(p.cm_mg_m3, 0.02137663748860852);
    close(p.xm_m, 369.73328243265895);
    close(p.um_m_s, 1.9300544685992504);
}

#[test]
fn cold_reference_and_low_wind_branches() {
    let mut r = sample();
    let s = &mut r.sources[0];
    s.height_m = 10.;
    s.gas_temperature_c = 20.;
    let p = s.parameters(200., 20.).unwrap();
    assert_eq!(p.regime, "cold_11");
    assert!(p.f.is_none());
    close(p.cm_mg_m3, 0.18617223498965062);
    close(p.xm_m, 148.2);
    close(p.um_m_s, 1.3);
    s.height_m = 30.;
    let p = s.parameters(200., 20.).unwrap();
    assert_eq!(p.regime, "cold_low_wind_13_14b");
    close(p.cm_mg_m3, 200. * 0.9 / 30_f64.powf(7. / 3.));
    close(p.xm_m, 171.);
    close(p.um_m_s, 0.5);
    s.gas_temperature_c = 21.;
    let p = s.parameters(200., 20.).unwrap();
    assert_eq!(p.regime, "cold_low_wind_13_14b"); // f >= 100
    s.exit_velocity_m_s = 0.1;
    s.outlet = Outlet::Circular { diameter_m: 0.1 };
    s.height_m = 10.;
    let p = s.parameters(200., 20.).unwrap();
    assert_eq!(p.regime, "warm_low_wind_13_14a");
    assert!(p.f_e < p.f.unwrap());
    let expected_m = 1. / (0.67 + 0.1 * p.f_e.sqrt() + 0.34 * p.f_e.cbrt());
    close(p.m.unwrap(), expected_m);
    close(p.cm_mg_m3, 200. * 2.86 * expected_m / 10_f64.powf(7. / 3.));
}

#[test]
fn cold_transition_and_high_velocity_branches() {
    let mut r = sample();
    let s = &mut r.sources[0];
    s.height_m = 10.;
    s.gas_temperature_c = 30.; // f=100 exactly
    assert_eq!(s.parameters(200., 20.).unwrap().regime, "cold_11");
    s.gas_temperature_c = 30.0001;
    assert_eq!(s.parameters(200., 20.).unwrap().regime, "warm_3");
    s.exit_velocity_m_s = 1.;
    s.gas_temperature_c = 20.4999;
    assert!(s.parameters(200., 20.).unwrap().regime.starts_with("cold"));
    s.gas_temperature_c = 20.5;
    assert!(s.parameters(200., 20.).unwrap().regime.starts_with("warm"));
    s.exit_velocity_m_s = 20.;
    s.gas_temperature_c = 20.;
    let p = s.parameters(200., 20.).unwrap();
    close(p.n.unwrap(), 1.);
    close(p.xm_m, 16. * 2.6_f64.sqrt() * 10.);
    close(p.um_m_s, 2.2 * 2.6);
    s.gas_temperature_c = 220.;
    let p = s.parameters(200., 20.).unwrap();
    close(p.n.unwrap(), 1.);
    close(
        p.xm_m,
        7. * p.v_m.sqrt() * (1. + 0.28 * p.f.unwrap().cbrt()) * 10.,
    );
    close(p.um_m_s, p.v_m * (1. + 0.12 * p.f.unwrap().sqrt()));
}

#[test]
fn rectangular_outlet_uses_effective_not_actual_volume() {
    let mut r = sample();
    r.sources[0].outlet = Outlet::Rectangular {
        length_m: 2.,
        width_m: 1.,
    };
    let rectangular = r.sources[0].parameters(200., 20.).unwrap();
    close(rectangular.effective_diameter_m, 4. / 3.);
    r.sources[0].outlet = Outlet::Circular {
        diameter_m: 4. / 3.,
    };
    let circular = r.sources[0].parameters(200., 20.).unwrap();
    close(rectangular.cm_mg_m3, circular.cm_mg_m3);
    close(
        rectangular.effective_volume_m3_s,
        circular.effective_volume_m3_s,
    );
}

#[test]
fn concentration_matches_cm_at_xm_and_um() {
    let mut r = sample();
    let p = r.sources[0].parameters(200., 20.).unwrap();
    r.receptors.truncate(1);
    r.receptors[0].x_m = 0.;
    r.receptors[0].y_m = p.xm_m;
    r.winds = vec![Wind {
        from_degrees: 180.,
        speed_m_s: p.um_m_s,
    }];
    close(
        calculate(&r).unwrap().receptors[0].sampled_max_mg_m3,
        p.cm_mg_m3,
    );
    r.sources[0].emission_g_s = 2.;
    close(
        calculate(&r).unwrap().receptors[0].sampled_max_mg_m3,
        2. * p.cm_mg_m3,
    );
    r.sources[0].emission_g_s = 0.;
    assert_eq!(calculate(&r).unwrap().receptors[0].sampled_max_mg_m3, 0.);
}

#[test]
fn direction_lateral_symmetry_and_upwind_zero() {
    let mut r = sample();
    r.receptors.truncate(1);
    r.receptors[0].x_m = 0.;
    r.receptors[0].y_m = 300.;
    r.winds = vec![Wind {
        from_degrees: 180.,
        speed_m_s: 2.,
    }];
    let axial = calculate(&r).unwrap().receptors[0].sampled_max_mg_m3;
    r.receptors[0].x_m = 100.;
    let east = calculate(&r).unwrap().receptors[0].sampled_max_mg_m3;
    assert!(east > 0. && east < axial);
    r.receptors[0].x_m = -100.;
    close(calculate(&r).unwrap().receptors[0].sampled_max_mg_m3, east);
    r.receptors[0].x_m = 0.;
    r.receptors[0].y_m = -300.;
    assert_eq!(calculate(&r).unwrap().receptors[0].sampled_max_mg_m3, 0.);
    r.receptors[0].x_m = 300.;
    r.receptors[0].y_m = 0.;
    r.winds[0].from_degrees = 270.;
    close(calculate(&r).unwrap().receptors[0].sampled_max_mg_m3, axial);
    r.winds[0].from_degrees = 90.;
    assert_eq!(calculate(&r).unwrap().receptors[0].sampled_max_mg_m3, 0.);
}

#[test]
fn sums_sources_at_common_wind_not_individual_maxima() {
    let mut r = sample();
    let original = calculate(&r).unwrap();
    let mut second = r.sources[0].clone();
    second.id = "second".into();
    r.sources.push(second);
    let doubled = calculate(&r).unwrap();
    for (a, b) in original.receptors.iter().zip(&doubled.receptors) {
        close(b.sampled_max_mg_m3, 2. * a.sampled_max_mg_m3);
        close(
            b.contributions_at_worst_mg_m3.iter().sum(),
            b.sampled_max_mg_m3,
        );
        assert_eq!(a.worst_sample_index, b.worst_sample_index);
    }
    // Receptor lies between opposed sources: never simultaneously downwind of both.
    r.sources[1].y_m = 600.;
    r.receptors.truncate(1);
    r.receptors[0].x_m = 0.;
    r.receptors[0].y_m = 300.;
    let result = calculate(&r).unwrap();
    let parts = &result.receptors[0].contributions_at_worst_mg_m3;
    assert_eq!(parts.iter().filter(|&&v| v > 0.).count(), 1);
}

#[test]
fn minimum_height_and_invalid_requests_are_explicit() {
    let mut r = sample();
    r.sources[0].height_m = 0.;
    close(
        r.sources[0]
            .parameters(200., 20.)
            .unwrap()
            .effective_height_m,
        2.,
    );
    type Mutation = Box<dyn Fn(&mut Request)>;
    let cases: Vec<Mutation> = vec![
        Box::new(|r| r.sources.clear()),
        Box::new(|r| r.winds.clear()),
        Box::new(|r| r.receptors.clear()),
        Box::new(|r| r.coefficient_a = f64::NAN),
        Box::new(|r| r.sources[0].emission_g_s = -1.),
        Box::new(|r| r.sources[0].exit_velocity_m_s = 0.),
        Box::new(|r| r.sources[0].exit_velocity_m_s = 331.),
        Box::new(|r| r.sources[0].gas_temperature_c = 19.),
        Box::new(|r| r.sources[0].height_m = -1.),
        Box::new(|r| r.sources[0].settling_factor = 0.),
        Box::new(|r| r.sources[0].outlet = Outlet::Circular { diameter_m: 0. }),
        Box::new(|r| r.sources.push(r.sources[0].clone())),
        Box::new(|r| r.receptors[0].height_m = 10.),
        Box::new(|r| r.receptors[0].x_m = 100_001.),
        Box::new(|r| r.receptors[0].y_m = f64::INFINITY),
        Box::new(|r| r.receptors.push(r.receptors[0].clone())),
        Box::new(|r| r.winds[0].speed_m_s = 0.4),
        Box::new(|r| r.winds[0].speed_m_s = 11.),
        Box::new(|r| r.winds[0].from_degrees = 361.),
        Box::new(|r| r.max_wind_speed_m_s = 5.),
    ];
    for (index, mutate) in cases.iter().enumerate() {
        let mut r = sample();
        mutate(&mut r);
        assert!(calculate(&r).is_err(), "case {index}");
    }
    let mut json = serde_json::to_value(sample()).unwrap();
    json["background"] = 1.into();
    assert!(serde_json::from_value::<Request>(json).is_err());
}
