use era_engine::{
    data::{Database, Row},
    engine::{Program, Runtime, Scenario},
    expr::{self, Value},
};
use std::{fs, path::PathBuf, sync::OnceLock};

fn db() -> &'static Database {
    static DB: OnceLock<Database> = OnceLock::new();
    DB.get_or_init(|| {
        let root = std::env::var_os("ERA_DATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../reverse_engineering/recovered")
            });
        Database::load(&root)
            .expect("Local corpus required: set ERA_DATA to the recovered JSON directory")
    })
}

fn scenario(name: &str) -> Scenario {
    serde_json::from_slice(
        &fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("examples/{name}.json")))
            .unwrap(),
    )
    .unwrap()
}

fn run(s: Scenario) -> era_engine::engine::RunResult {
    let p = Program::compile(&s.method, &db().methods[&s.method]).unwrap();
    Runtime::new(db(), s).run(&p).unwrap()
}

fn close(a: f64, b: f64) {
    assert!((a - b).abs() <= 1e-12 * b.abs().max(1.), "{a} != {b}");
}

fn number(r: &era_engine::engine::RunResult, n: &str) -> f64 {
    r.variables[n].number().unwrap()
}

#[test]
fn full_washing() {
    let r = run(scenario("washing"));
    close(number(&r, "_g_"), 0.866);
    close(number(&r, "_m_"), 6.2352);
    assert_eq!(r.variables["_v_"], Value::Text("2732".into()));
    assert!(r.steps > 30);
    assert!(r.trace.iter().any(|r| r.record == 13917));
}

#[test]
fn all_washing_table_rows() {
    for i in 2..=5 {
        let mut s = scenario("washing");
        s.selections.insert(16, vec![i]);
        let r = run(s);
        close(number(&r, "_g_"), 0.0032);
        close(number(&r, "_m_"), 0.02304);
        assert_eq!(r.variables["_v_"], Value::Text("0155".into()));
    }
}

#[test]
fn battery_both_electrolytes() {
    for (choice, factor, code) in [(1, 1., "0322"), (2, 0.8, "0150")] {
        let mut s = scenario("battery_acid");
        s.selections.insert(27, vec![choice]);
        let r = run(s);
        close(number(&r, "_m_"), 0.000054 * factor);
        close(number(&r, "_g_"), 0.000015 * factor);
        assert_eq!(r.variables["_v_"], Value::Text(code.into()));
    }
}

#[test]
fn battery_melting_branch() {
    let r = run(scenario("battery_melting"));
    close(number(&r, "_m_"), 0.0000936);
    close(number(&r, "_g_"), 0.00026);
    assert_eq!(r.variables["_v_"], Value::Text("0184".into()));
}

#[test]
fn battery_loop_with_input_queues() {
    let mut s = scenario("battery_acid");
    s.selections.insert(27, vec![1, 2]);
    s.prompts
        .insert(51, vec![Value::Number(1.), Value::Number(0.)]);
    s.prompts
        .insert(32, vec![Value::Number(60.), Value::Number(100.)]);
    let r = run(s);
    assert_eq!(r.writes.len(), 4);
    close(r.writes[0].value, 0.000054);
    close(r.writes[2].value, 0.000072);
    assert_eq!(r.writes[2].pollutant, "0150");
}

#[test]
fn fuel_two_coefficients() {
    for (choice, gi) in [(1, 317.), (2, 788.)] {
        let mut s = scenario("fuel_testing");
        s.selections.insert(15, vec![choice]);
        let r = run(s);
        close(number(&r, "_m_"), gi / 1000.);
        close(number(&r, "_g_"), 10. * gi / 8. / 3600.);
    }
}

#[test]
fn fuel_washing_branch() {
    let mut s = scenario("fuel_testing");
    s.selections.insert(15, vec![3]);
    s.inputs.insert("F".into(), Value::Number(2.));
    s.inputs.insert("n".into(), Value::Number(250.));
    let r = run(s);
    close(number(&r, "_g_"), 0.866);
    close(number(&r, "_m_"), 6.2352);
}

#[test]
fn tire_repair_branch() {
    let r = run(scenario("tire_repair"));
    let gb = number(&r, "gb");
    assert!(gb > 0.);
    close(number(&r, "_g_"), gb);
    close(number(&r, "_m_"), gb * 14.4);
}

#[test]
fn no_silent_missing_input() {
    let mut s = scenario("washing");
    s.inputs.remove("F");
    let p = Program::compile(&s.method, &db().methods[&s.method]).unwrap();
    let e = Runtime::new(db(), s).run(&p).unwrap_err();
    assert!(e.contains("Input required: f"), "{e}");
}

#[test]
fn no_silent_table_choice() {
    let mut s = scenario("washing");
    s.selections.clear();
    let p = Program::compile(&s.method, &db().methods[&s.method]).unwrap();
    assert!(Runtime::new(db(), s)
        .run(&p)
        .unwrap_err()
        .contains("TAB selection required"));
}

#[test]
fn placeholder_is_not_an_algorithm() {
    assert!(Program::compile("0104", &db().methods["0104"]).is_err());
}

#[test]
fn oxygen_variable_is_not_a_logical_operator() {
    let mut r = Runtime::new(db(), Scenario::default());
    for (key, value) in [("cr", 70.), ("sr", 2.), ("hr", 5.), ("or", 10.)] {
        r.variables.insert(key.into(), Value::Number(value));
    }
    let formula = "0.0889*(Cr+0.375*Sr)+0.265*Hr-0.0333*Or";
    close(
        r.eval(&expr::parse(formula).unwrap())
            .unwrap()
            .number()
            .unwrap(),
        0.0889 * (70. + 0.375 * 2.) + 0.265 * 5. - 0.0333 * 10.,
    );
    for expression in ["Or=10 OR 1=0", "Or=10.and.1=1", "not Or=0", "1=0 or Or=10"] {
        assert_eq!(
            r.eval(&expr::parse(expression).unwrap()).unwrap(),
            Value::Bool(true)
        );
    }
    for method in ["0041", "0042", "0054", "0057", "0059"] {
        assert!(db().methods[method]
            .iter()
            .any(|row| row.formula == formula));
        for row in db().methods[method]
            .iter()
            .filter(|row| row.formula == formula)
        {
            assert!(expr::statement(&row.formula).is_ok());
        }
    }
}

#[test]
fn filtered_table() {
    let mut r = Runtime::new(
        db(),
        Scenario {
            method: "0092".into(),
            ..Scenario::default()
        },
    );
    close(
        r.eval(&expr::parse("TAB(130,(1)[4]>0.01,4)").unwrap())
            .unwrap()
            .number()
            .unwrap(),
        0.433,
    );
}

#[test]
fn parallel_batch_preserves_order_and_numbers() {
    let cases = vec![
        scenario("washing"),
        scenario("battery_acid"),
        scenario("fuel_testing"),
        scenario("battery_melting"),
    ];
    let serial = era_engine::run_batch(db(), &cases, 1).unwrap();
    let parallel = era_engine::run_batch(db(), &cases, 3).unwrap();
    assert_eq!(
        serde_json::to_value(serial).unwrap(),
        serde_json::to_value(parallel).unwrap()
    );
}

#[test]
fn batch_failure_is_explicit() {
    let mut bad = scenario("washing");
    bad.inputs.remove("F");
    let error = era_engine::run_batch(db(), &[scenario("washing"), bad], 2).unwrap_err();
    assert!(error.contains("batch case 1"));
    assert!(error.contains("Input required"));
    assert!(era_engine::run_batch(db(), &[], 0).is_err());
}

#[test]
fn published_metal_report_fragments() {
    let formulas = |lines: &[usize]| -> Vec<Row> {
        lines
            .iter()
            .map(|n| {
                db().methods["0074"]
                    .iter()
                    .find(|r| r.line == *n)
                    .unwrap()
                    .clone()
            })
            .collect()
    };
    for (gv, g, m) in [(0.02, 0.0003, 0.00147), (0.03, 0.00045, 0.002203)] {
        let p = Program::compile("0074", &formulas(&[544, 582, 589])).unwrap();
        let mut s = Scenario {
            method: "0074".into(),
            ..Scenario::default()
        };
        for (k, v) in [("gv", gv), ("ti", 900.), ("t", 1020.), ("kn", 0.2)] {
            s.initial.insert(k.into(), Value::Number(v));
        }
        let r = Runtime::new(db(), s).run(&p).unwrap();
        close(number(&r, "miv20"), g);
        assert!((number(&r, "migv") - m).abs() < 0.000005);
    }
    let p = Program::compile("0074", &formulas(&[464, 482, 485, 477])).unwrap();
    let mut s = Scenario {
        method: "0074".into(),
        ..Scenario::default()
    };
    for (k, v) in [
        ("gv1", 1.035),
        ("ti", 900.),
        ("t", 1020.),
        ("nod", 8.),
        ("knfsog", 0.),
    ] {
        s.initial.insert(k.into(), Value::Number(v));
    }
    let r = Runtime::new(db(), s).run(&p).unwrap();
    close(number(&r, "misogv"), 0.00002484);
    assert!((number(&r, "misogg") - 0.0001216).abs() < 0.00000005);
}
