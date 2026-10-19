//! Synthetic example, authored for this project, with no vendor data dependency.
use crate::{
    data::{Database, Row},
    engine::{Program, RunResult, Runtime, Scenario},
    expr::Value,
    Result,
};

pub fn run() -> Result<RunResult> {
    let method = "DEMO";
    let rows: Vec<Row> = [
        ("_v_", "'DEMO-DUST'"),
        ("rate", "factor*units"),
        ("_g_", "rate"),
        ("_m_", "rate*hours*3600/1000000"),
        ("", "Конец"),
    ]
    .iter()
    .enumerate()
    .map(|(i, (variable, formula))| Row {
        method: method.into(),
        line: i + 1,
        label: None,
        variable: (*variable).into(),
        formula: (*formula).into(),
        description: "Synthetic example; not an environmental assessment".into(),
        record: i + 1,
    })
    .collect();
    let db = Database::default();
    let program = Program::compile(method, &rows)?;
    let mut scenario = Scenario {
        method: method.into(),
        trace: true,
        ..Scenario::default()
    };
    for (name, value) in [("factor", 0.25), ("units", 4.), ("hours", 1000.)] {
        scenario.initial.insert(name.into(), Value::Number(value));
    }
    Runtime::new(&db, scenario).run(&program)
}
