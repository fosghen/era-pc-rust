use era_engine::{
    data::{Database, Row},
    engine::{Program, Runtime, Scenario},
    expr::{self, Value},
};
use std::{fs, path::PathBuf, sync::OnceLock};
fn db() -> &'static Database {
    static DB: OnceLock<Database> = OnceLock::new();
    DB.get_or_init(|| {
        Database::load(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../reverse_engineering/recovered"),
        )
        .unwrap()
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
fn expression_rules() {
    let mut r = Runtime::new(db(), Scenario::default());
    for (s, value) in [
        ("2^3^2", 512.),
        ("-2^2", -4.),
        ("10^-6", 0.000001),
        ("ROUND(-1.25,1)", -1.3),
        ("iif(1=1,7,1/0)", 7.),
    ] {
        close(
            r.eval(&expr::parse(s).unwrap()).unwrap().number().unwrap(),
            value,
        );
    }
    assert_eq!(
        r.eval(&expr::parse("1=1.и..not.(2=3)").unwrap()).unwrap(),
        Value::Bool(true)
    );
    assert!(r.eval(&expr::parse("1/0").unwrap()).is_err());
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
fn group_array_assignment_linear_index_and_resize() {
    let p = synthetic(&[
        ("", "Dimension _M1_(2,3), _M2_(2,2)", 0),
        ("", "Store 0 to _M1_,_M2_", 0),
        ("", "_M1_(1),_M1_(2)='*'", 0),
        ("", "store 7 to a,b,_M1_(2,1),_M2_(1,2)", 0),
        ("s", "_M1_(1,1)+_M1_(1,2)", 0),
        ("linear", "_M1_(4)", 0),
        ("", "Dimension _M1_(3,3)", 0),
        ("preserved", "_M1_(2,1)", 0),
        ("new", "_M1_(9)", 0),
        ("", "Dimension _M1_(4)", 0),
        ("shrunk", "_M1_(4)", 0),
        ("other", "_M2_(2)", 0),
    ]);
    let r = Runtime::new(
        db(),
        Scenario {
            method: "test".into(),
            ..Scenario::default()
        },
    )
    .run(&p)
    .unwrap();
    for name in ["a", "b", "linear", "preserved", "shrunk", "other"] {
        close(number(&r, name), 7.);
    }
    assert_eq!(r.variables["s"], Value::Text("**".into()));
    assert_eq!(r.variables["new"], Value::Bool(false));
}

#[test]
fn array_aggregate_rows_columns_and_negative_maximum() {
    let p = synthetic(&[
        ("", "Dimension _M1_(2,3)", 0),
        ("", "store -2 to _M1_", 0),
        ("", "store -5 to _M1_(2,2)", 0),
        ("sumrow", "_ASUM('_M1_',2,0,1,3)", 0),
        ("sumcol", "_ASUM('_M1_',0,2,1,2)", 0),
        ("maxrow", "_AMAX('_M1_',2,0,1,3)", 0),
        ("maxcol", "_AMAX('_M1_',0,2,1,2)", 0),
    ]);
    let r = Runtime::new(
        db(),
        Scenario {
            method: "test".into(),
            ..Scenario::default()
        },
    )
    .run(&p)
    .unwrap();
    close(number(&r, "sumrow"), -9.);
    close(number(&r, "sumcol"), -7.);
    close(number(&r, "maxrow"), -2.);
    close(number(&r, "maxcol"), -2.);
}

#[test]
fn array_invalid_indices_dimensions_and_targets_fail() {
    for formula in [
        "store 1 to _M1_(0)",
        "store 1 to _M1_(101)",
        "store 1 to _M1_(1,3)",
        "Dimension _M1_(0,3)",
        "Dimension _M1_(1000000,1000000)",
        "x=_ASUM('_M1_',0,0,1,2)",
        "x=_AMAX('_M1_',1,0,3,2)",
        "x=_ASUM('_M1_',1,0,1,3)",
        "store 1 to sin(1)",
    ] {
        let p = synthetic(&[("", formula, 0), ("", "Конец", 0)]);
        assert!(
            Runtime::new(
                db(),
                Scenario {
                    method: "test".into(),
                    ..Scenario::default()
                }
            )
            .run(&p)
            .is_err(),
            "{formula}"
        );
    }
    for formula in ["Dimension x", "Dimension _M1_(1,2,3)"] {
        assert!(expr::statement(formula).is_err(), "{formula}");
    }
}

#[test]
fn named_arrays_from_recovered_methods() {
    let p = synthetic(&[
        ("", "Dimension Pzv(7,2),_MU_(10)", 0),
        ("", "store '0337' to Pzv(1,1)", 0),
        ("", "store 3 to Pzv(1,2)", 0),
        ("", "store 0 to _MU_", 0),
        ("", "store 7 to _MU_(1)", 0),
        ("code", "Pzv(1,1)", 0),
        ("value", "Pzv(2)+_MU_(1)", 0),
    ]);
    let r = Runtime::new(
        db(),
        Scenario {
            method: "test".into(),
            ..Scenario::default()
        },
    )
    .run(&p)
    .unwrap();
    assert_eq!(r.variables["code"], Value::Text("0337".into()));
    close(number(&r, "value"), 10.);
}

fn table_fixture() -> Database {
    use era_engine::data::{Column, TableRow};
    let mut db = Database::default();
    db.tables.insert(
        ("test".into(), "1".into(), false),
        vec![
            TableRow {
                number: 1,
                record: 1,
                cells: vec!["A".into(), "X".into(), "3".into()],
                mark: String::new(),
            },
            TableRow {
                number: 2,
                record: 2,
                cells: vec!["A".into(), "Y".into(), "5".into()],
                mark: "*".into(),
            },
            TableRow {
                number: 3,
                record: 3,
                cells: vec!["B".into(), "X".into(), "7".into()],
                mark: String::new(),
            },
        ],
    );
    for (n, kind, dictionary) in [(1, "К", "a"), (2, "К", "b"), (3, "Ч", "")] {
        db.columns.insert(
            ("test".into(), "1".into(), n),
            Column {
                kind: kind.into(),
                dictionary: dictionary.into(),
                name: format!("c{n}"),
            },
        );
    }
    db.tables.insert(
        ("test".into(), "1".into(), true),
        vec![
            TableRow {
                number: 1,
                record: 10,
                cells: vec!["A".into(), "Alpha".into()],
                mark: String::new(),
            },
            TableRow {
                number: 2,
                record: 11,
                cells: vec!["B".into(), "Beta".into()],
                mark: "*".into(),
            },
        ],
    );
    db
}

#[test]
fn filtered_table_requires_explicit_valid_choice() {
    let db = table_fixture();
    let e = expr::parse("TAB(1,[3]>=5,3)").unwrap();
    let s = Scenario {
        method: "test".into(),
        ..Scenario::default()
    };
    assert!(Runtime::new(&db, s.clone())
        .eval(&e)
        .unwrap_err()
        .contains("TAB selection required"));
    let mut s = s;
    s.selections.insert(0, vec![3]);
    close(
        Runtime::new(&db, s.clone())
            .eval(&e)
            .unwrap()
            .number()
            .unwrap(),
        7.,
    );
    s.selections.insert(0, vec![1]);
    assert!(Runtime::new(&db, s)
        .eval(&e)
        .unwrap_err()
        .contains("outside the matching rows"));
}

#[test]
fn implicit_table_key_and_start_expression() {
    let db = table_fixture();
    let mut r = Runtime::new(
        &db,
        Scenario {
            method: "test".into(),
            ..Scenario::default()
        },
    );
    for (formula, expected) in [
        ("TAB(1,(1)='AY',3)", 5.),
        ("TAB(1,((1+1))[3]>=5,3)", 5.),
        ("TAB(1,(3)[3]>=5,3)", 7.),
    ] {
        close(
            r.eval(&expr::parse(formula).unwrap())
                .unwrap()
                .number()
                .unwrap(),
            expected,
        );
    }
    assert_eq!(
        r.eval(&expr::parse("TAB(1,(1)='*',21)").unwrap()).unwrap(),
        Value::Text("*".into())
    );
    assert_eq!(
        r.eval(&expr::parse("TAB(1,(1)[3]>9,3)").unwrap()).unwrap(),
        Value::Text(String::new())
    );
    close(r.variables["_nvib_"].number().unwrap(), 0.);
    r.eval(&expr::parse("TAB(1,99,3)").unwrap()).unwrap();
    close(r.variables["_err_"].number().unwrap(), 4018.);
}

#[test]
fn dictionary_physical_row_is_distinct_from_ordinal() {
    let db = table_fixture();
    let mut r = Runtime::new(
        &db,
        Scenario {
            method: "test".into(),
            ..Scenario::default()
        },
    );
    r.eval(&expr::parse("TAB(1(s),1,2)").unwrap()).unwrap();
    close(r.variables["_row_"].number().unwrap(), 10.);
    assert_eq!(
        r.eval(&expr::parse("TAB(1(s),_Row_+1,2)").unwrap())
            .unwrap(),
        Value::Text("Beta".into())
    );
    assert_eq!(
        r.eval(&expr::parse("TAB(1(s),(1)='B',2)").unwrap())
            .unwrap(),
        Value::Text("Beta".into())
    );
    r.variables.insert("saved".into(), Value::Number(10.));
    r.eval(&expr::parse("TAB(1(s),saved+1,2)").unwrap())
        .unwrap();
    close(r.variables["_nvib_"].number().unwrap(), 0.);
    r.eval(&expr::parse("TAB(1,1,3)").unwrap()).unwrap();
    assert_eq!(r.variables["_kod_"], Value::Text(String::new()));
    assert_eq!(r.variables["_name_"], Value::Text(String::new()));
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
fn unknown_host_callback_fails() {
    let mut r = Runtime::new(db(), Scenario::default());
    assert!(r
        .eval(&expr::parse("indll('metz0080')").unwrap())
        .unwrap_err()
        .contains("Unimplemented function"));
}
#[test]
fn malformed_expressions() {
    for s in ["(", "1+", "TAB(", "'abc", "a(1,,2)", "[x]"] {
        assert!(expr::parse(s).is_err(), "{s}");
    }
}

fn synthetic(lines: &[(&str, &str, usize)]) -> Program {
    let rows: Vec<_> = lines
        .iter()
        .enumerate()
        .map(|(i, (variable, formula, label))| Row {
            method: "test".into(),
            line: i + 1,
            label: Some(*label),
            variable: (*variable).into(),
            formula: (*formula).into(),
            description: String::new(),
            record: i + 1,
        })
        .collect();
    Program::compile("test", &rows).unwrap()
}
#[test]
fn control_flow_arrays_and_multiple_assignment() {
    let p = synthetic(&[
        ("", "a,b=0", 0),
        ("", "Dimension _M1_(2,2)", 0),
        ("a", "a+1", 10),
        ("", "Store a*2 to _M1_(a,1)", 0),
        ("", "Если a<2, шаг 10", 0),
        ("b", "_M1_(2,1)", 0),
        ("", "Конец", 0),
        ("b", "1/0", 0),
    ]);
    let r = Runtime::new(
        db(),
        Scenario {
            method: "test".into(),
            ..Scenario::default()
        },
    )
    .run(&p)
    .unwrap();
    close(number(&r, "b"), 4.);
}
#[test]
fn loop_limit() {
    let p = synthetic(&[("", "шаг 1", 1), ("", "Конец", 0)]);
    let s = Scenario {
        method: "test".into(),
        max_steps: 10,
        ..Scenario::default()
    };
    assert!(Runtime::new(db(), s)
        .run(&p)
        .unwrap_err()
        .contains("Step limit"));
}

#[test]
fn dynamic_jump_and_project_field() {
    let p = synthetic(&[
        ("", "store 42 to destination", 0),
        ("", "шаг destination", 0),
        ("answer", "1/0", 0),
        ("answer", "Если ngor.kno_=2 и 3>1, 7, 0", 42),
    ]);
    let mut s = Scenario {
        method: "test".into(),
        ..Scenario::default()
    };
    s.initial.insert("ngor.kno_".into(), Value::Number(2.));
    let r = Runtime::new(db(), s).run(&p).unwrap();
    close(number(&r, "answer"), 7.);
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
