use era_engine::{
    data::{Column, Database, TableRow},
    engine::{Runtime, Scenario},
    expr::{self, Value},
    range::NumericRange,
};

fn fixture() -> Database {
    let mut db = Database::default();
    db.tables.insert(
        ("test".into(), "1".into(), false),
        vec![
            TableRow {
                number: 1,
                record: 1,
                cells: vec!["10-20".into(), "3".into(), "".into()],
                mark: String::new(),
            },
            TableRow {
                number: 2,
                record: 2,
                cells: vec!["30-40".into(), "5".into(), "".into()],
                mark: String::new(),
            },
        ],
    );
    for (col, kind) in [(1, "Д"), (2, "Ч"), (3, "Д")] {
        db.columns.insert(
            ("test".into(), "1".into(), col),
            Column {
                kind: kind.into(),
                dictionary: String::new(),
                name: String::new(),
            },
        );
    }
    db
}
fn scenario() -> Scenario {
    Scenario {
        method: "test".into(),
        ..Scenario::default()
    }
}
fn eval(rt: &mut Runtime, expression: &str) -> era_engine::Result<Value> {
    rt.eval(&expr::parse(expression)?)
}

#[test]
fn parse_numbers_signed_scientific_and_descending_ranges() {
    for (s, min, max) in [
        ("2", 2., 2.),
        ("18-14", 14., 18.),
        ("-5--2", -5., -2.),
        ("1e-3-2e-3", 0.001, 0.002),
        (" -2 – +3 ", -2., 3.),
        ("0—1", 0., 1.),
    ] {
        assert_eq!(NumericRange::parse(s).unwrap(), NumericRange { min, max });
    }
    for bad in ["", "-", "1-2-3", "NaN", "inf", "1e999", "x-y", "0.1-NaN"] {
        assert!(NumericRange::parse(bad).is_err(), "{bad}");
    }
}
#[test]
fn interpolation_is_explicit_and_validated() {
    let db = fixture();
    let mut rt = Runtime::new(&db, scenario());
    assert!(eval(&mut rt, "TAB(1,1,1)")
        .unwrap_err()
        .contains("explicit _Diap_"));
    for (fraction, expected) in [(0., 10.), (0.25, 12.5), (0.5, 15.), (1., 20.)] {
        rt.variables
            .insert("_diap_".into(), Value::Number(fraction));
        assert_eq!(
            eval(&mut rt, "TAB(1,1,1)").unwrap(),
            Value::Number(expected)
        );
        assert_eq!(rt.variables["_mind_"], Value::Number(10.));
        assert_eq!(rt.variables["_maxd_"], Value::Number(20.));
    }
    for bad in [-0.01, 1.01, f64::NAN, f64::INFINITY] {
        rt.variables.insert("_diap_".into(), Value::Number(bad));
        assert!(eval(&mut rt, "TAB(1,1,1)").is_err());
    }
}
#[test]
fn membership_includes_endpoints_and_does_not_need_interpolation() {
    let db = fixture();
    let mut rt = Runtime::new(&db, scenario());
    for x in [10., 15., 20.] {
        rt.variables.insert("x".into(), Value::Number(x));
        assert_eq!(
            eval(&mut rt, "TAB(1,(1)[1]$x,2)").unwrap(),
            Value::Number(3.)
        );
    }
    rt.variables.insert("x".into(), Value::Number(25.));
    eval(&mut rt, "TAB(1,(1)[1]$x,2)").unwrap();
    assert_eq!(rt.variables["_nvib_"], Value::Number(0.));
    assert!(eval(&mut rt, "TAB(1,(1)[2]$3,2)")
        .unwrap_err()
        .contains("range-valued"));
}
#[test]
fn comparison_uses_interpolation_and_unrelated_blank_cells_are_not_read() {
    let db = fixture();
    let mut rt = Runtime::new(&db, scenario());
    rt.variables.insert("_diap_".into(), Value::Number(0.5));
    assert_eq!(
        eval(&mut rt, "TAB(1,(1)[1]>=30,2)").unwrap(),
        Value::Number(5.)
    );
    assert_eq!(
        eval(&mut rt, "TAB(1,(1)[2]=3,2)").unwrap(),
        Value::Number(3.)
    );
    assert!(eval(&mut rt, "TAB(1,1,3)").is_err());
    assert!(eval(&mut rt, "TAB(1,(1)[3]>0,2)").is_err());
    // Failed nested evaluation cannot leak the table's column context.
    assert!(eval(&mut rt, "[1]")
        .unwrap_err()
        .contains("outside a TAB search"));
}
