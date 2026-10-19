use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Row {
    #[serde(rename = "KOD_MET_")]
    pub method: String,
    #[serde(rename = "N_STR_")]
    pub line: usize,
    #[serde(rename = "METKA_")]
    pub label: Option<usize>,
    #[serde(rename = "N_VAR_")]
    pub variable: String,
    pub formula: String,
    #[serde(rename = "TXT_")]
    pub description: String,
    #[serde(rename = "_record")]
    pub record: usize,
}
#[derive(Deserialize)]
struct Rows<T> {
    rows: Vec<T>,
}
#[derive(Clone, Debug)]
pub struct TableRow {
    pub number: usize,
    pub record: usize,
    pub cells: Vec<String>,
    pub mark: String,
}
#[derive(Clone, Debug)]
pub struct Column {
    pub kind: String,
    pub dictionary: String,
    pub name: String,
}
#[derive(Clone, Debug, Default)]
pub struct Database {
    pub methods: BTreeMap<String, Vec<Row>>,
    pub tables: BTreeMap<(String, String, bool), Vec<TableRow>>,
    pub columns: BTreeMap<(String, String, usize), Column>,
}
pub fn table_id(s: &str) -> String {
    let t = s.trim();
    if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
        t.parse::<u32>()
            .map(|v| v.to_string())
            .unwrap_or_else(|_| t.to_lowercase())
    } else {
        t.to_lowercase()
    }
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?)
        .map_err(|e| format!("{}: {e}", path.display()))
}
fn text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or("").to_string()
}
impl Database {
    pub fn load(root: &Path) -> Result<Self> {
        let mut db = Self::default();
        for row in read::<Rows<Row>>(&root.join("algorithms.json"))?.rows {
            db.methods.entry(row.method.clone()).or_default().push(row);
        }
        for rows in db.methods.values_mut() {
            rows.sort_by_key(|r| (r.line, r.record));
        }
        for v in read::<Rows<Value>>(&root.join("tables/tabl.json"))?.rows {
            db.tables
                .entry((text(&v, "KOD_MET_"), table_id(&text(&v, "NTAB_")), false))
                .or_default()
                .push(TableRow {
                    number: v["N_STR_"].as_u64().unwrap_or(0) as usize,
                    record: v["_record"].as_u64().unwrap_or(0) as usize,
                    cells: (1..=20).map(|n| text(&v, &format!("N{n}_"))).collect(),
                    mark: text(&v, "VIEW_"),
                });
        }
        for rows in db.tables.values_mut() {
            rows.sort_by_key(|r| r.number);
        }
        for v in read::<Rows<Value>>(&root.join("tables/tablvoc.json"))?.rows {
            let rows = db
                .tables
                .entry((text(&v, "KOD_MET_"), table_id(&text(&v, "NTAB_")), true))
                .or_default();
            rows.push(TableRow {
                number: rows.len() + 1,
                record: v["_record"].as_u64().unwrap_or(0) as usize,
                cells: vec![text(&v, "KOD_STR_"), text(&v, "TXT_")],
                mark: text(&v, "VIEW_"),
            });
        }
        for v in read::<Rows<Value>>(&root.join("tables/tablop.json"))?.rows {
            db.columns.insert(
                (
                    text(&v, "KOD_MET_"),
                    table_id(&text(&v, "NTAB_")),
                    v["N_KOL_"].as_u64().unwrap_or(0) as usize,
                ),
                Column {
                    kind: text(&v, "TIP_"),
                    dictionary: table_id(&text(&v, "SLOV_")),
                    name: text(&v, "NAME_KOL_").to_lowercase(),
                },
            );
        }
        Ok(db)
    }
}
