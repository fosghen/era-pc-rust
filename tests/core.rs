use era_engine::{
    data::{Database, Row},
    engine::{Program, Runtime, Scenario},
    expr::{self, Value},
};
use std::sync::OnceLock;

fn db() -> &'static Database {
    static DB: OnceLock<Database> = OnceLock::new();
    DB.get_or_init(Database::default)
}

fn close(a: f64, b: f64) {
    assert!((a - b).abs() <= 1e-12 * b.abs().max(1.), "{a} != {b}");
}

fn number(r: &era_engine::engine::RunResult, n: &str) -> f64 {
    r.variables[n].number().unwrap()
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
