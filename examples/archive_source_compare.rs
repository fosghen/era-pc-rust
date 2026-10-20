//! Offline comparison with saved archive exports, not a live ERA oracle.
//! Only individual-source Cm/PDK, Um and Xm are compared; no target is executed.
use era_engine::dispersion::PointSource;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_CASES: usize = 10_000;
const MAX_PRINTED: usize = 32;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
enum Provenance {
    Archive {
        archive_name: String,
        archive_sha256: String,
    },
    Project {
        project_name: String,
        selected_files_manifest_sha256: String,
    },
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    member: String,
    sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    cm_pdk: String,
    um_m_s: String,
    xm_m: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    case_id: String,
    coefficient_a: f64,
    air_temperature_c: f64,
    pdk_mg_m3: f64,
    source: PointSource,
    expected: Expected,
    evidence: Vec<Evidence>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Skipped {
    case_id: String,
    reason: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: u32,
    provenance: Provenance,
    cases: Vec<Case>,
    skipped: Vec<Skipped>,
}

#[derive(Debug)]
struct Printed {
    numerator: u128,
    scale: u128,
    value: f64,
}

fn printed(s: &str) -> Result<Printed, String> {
    if s.is_empty() || s.len() > MAX_PRINTED {
        return Err("Expected value must contain 1..=32 characters".into());
    }
    let (whole, fraction) = match s.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
        Some(_) => return Err("Expected fixed decimal cannot end with a dot".into()),
        None => (s, ""),
    };
    if whole.is_empty()
        || fraction.len() > 12
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return Err("Expected value must be a nonnegative fixed decimal with <=12 decimals".into());
    }
    let numerator = whole
        .bytes()
        .chain(fraction.bytes())
        .fold(0u128, |n, b| n * 10 + u128::from(b - b'0'));
    let value = s.parse::<f64>().map_err(|e| e.to_string())?;
    if !value.is_finite() {
        return Err("Expected value must be finite".into());
    }
    Ok(Printed {
        numerator,
        scale: 10u128.pow(fraction.len() as u32),
        value,
    })
}

// Compare left * 2^exponent with right exactly, without overflowing u128.
fn compare_binary_integer(left: u128, exponent: i32, right: u128) -> Ordering {
    if left == 0 || right == 0 {
        return left.cmp(&right);
    }
    let left_bits = 128 - left.leading_zeros() as i32 + exponent;
    let right_bits = 128 - right.leading_zeros() as i32;
    match left_bits.cmp(&right_bits) {
        Ordering::Equal if exponent >= 0 => (left << exponent).cmp(&right),
        Ordering::Equal => left.cmp(&(right << -exponent)),
        other => other,
    }
}

// f64 is an exact binary rational. Compare against a decimal interval before
// rounding either boundary to f64; no extra numerical tolerance is introduced.
fn within_rounding_interval(actual: f64, expected: &Printed) -> bool {
    let bits = actual.to_bits();
    let biased_exponent = ((bits >> 52) & 0x7ff) as i32;
    let mantissa =
        u128::from(bits & ((1u64 << 52) - 1)) + if biased_exponent == 0 { 0 } else { 1u128 << 52 };
    let exponent = if biased_exponent == 0 {
        -1074
    } else {
        biased_exponent - 1023 - 52
    };
    let scaled = mantissa * (2 * expected.scale);
    let center = 2 * expected.numerator;
    (center == 0 || compare_binary_integer(scaled, exponent, center - 1) != Ordering::Less)
        && compare_binary_integer(scaled, exponent, center + 1) != Ordering::Greater
}

#[derive(Debug, Serialize)]
struct Metric {
    actual: f64,
    expected: String,
    allowed_rounding_half_step: f64,
    error: f64,
    absolute_error: f64,
    pass: bool,
}
fn metric(actual: f64, expected: &str) -> Result<Metric, String> {
    if !actual.is_finite() || actual < 0. {
        return Err("Calculated value must be finite and nonnegative".into());
    }
    let decimal = printed(expected)?;
    let error = actual - decimal.value;
    Ok(Metric {
        actual,
        expected: expected.into(),
        allowed_rounding_half_step: 0.5 / decimal.scale as f64,
        error,
        absolute_error: error.abs(),
        pass: within_rounding_interval(actual, &decimal),
    })
}

#[derive(Debug, Serialize)]
struct Metrics {
    cm_pdk: Metric,
    um_m_s: Metric,
    xm_m: Metric,
}
#[derive(Debug, Serialize)]
struct CaseReport {
    case_id: String,
    pdk_mg_m3: f64,
    evidence: Vec<Evidence>,
    metrics: Metrics,
    pass: bool,
}
#[derive(Debug, Serialize)]
struct Summary {
    compared: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    all_passed: bool,
}
#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    scope: &'static str,
    limitations: [&'static str; 4],
    provenance: Provenance,
    summary: Summary,
    cases: Vec<CaseReport>,
    skipped: Vec<Skipped>,
}

fn bounded_text(name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(format!("Invalid bounded {name}"))
    } else {
        Ok(())
    }
}
fn sha256(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("SHA256 must be 64 hex characters".into())
    }
}

fn compare(input: Input) -> Result<Report, String> {
    if input.schema_version != 1 {
        return Err("Unsupported schema_version".into());
    }
    if input.cases.is_empty() || input.cases.len() > MAX_CASES || input.skipped.len() > MAX_CASES {
        return Err("Require 1..=10000 cases and <=10000 skipped entries".into());
    }
    match &input.provenance {
        Provenance::Archive {
            archive_name,
            archive_sha256,
        } => {
            bounded_text("archive_name", archive_name, 1024)?;
            sha256(archive_sha256)?;
        }
        Provenance::Project {
            project_name,
            selected_files_manifest_sha256,
        } => {
            bounded_text("project_name", project_name, 1024)?;
            sha256(selected_files_manifest_sha256)?;
        }
    }
    let mut ids = BTreeSet::new();
    for id in input
        .cases
        .iter()
        .map(|c| &c.case_id)
        .chain(input.skipped.iter().map(|s| &s.case_id))
    {
        bounded_text("case_id", id, 512)?;
        if !ids.insert(id.clone()) {
            return Err(format!("Duplicate case_id: {id}"));
        }
    }
    for skipped in &input.skipped {
        bounded_text("skipped reason", &skipped.reason, 4096)?;
    }
    let mut cases = Vec::with_capacity(input.cases.len());
    for case in input.cases {
        let result = (|| {
            if !case.pdk_mg_m3.is_finite() || case.pdk_mg_m3 <= 0. {
                return Err("pdk_mg_m3 must be positive and finite".into());
            }
            if case.evidence.is_empty() || case.evidence.len() > 64 {
                return Err("Require 1..=64 evidence members".into());
            }
            for item in &case.evidence {
                bounded_text("evidence member", &item.member, 1024)?;
                sha256(&item.sha256)?;
            }
            let parameters = case
                .source
                .parameters(case.coefficient_a, case.air_temperature_c)?;
            let metrics = Metrics {
                cm_pdk: metric(parameters.cm_mg_m3 / case.pdk_mg_m3, &case.expected.cm_pdk)?,
                um_m_s: metric(parameters.um_m_s, &case.expected.um_m_s)?,
                xm_m: metric(parameters.xm_m, &case.expected.xm_m)?,
            };
            Ok::<_, String>(metrics)
        })()
        .map_err(|error| format!("Case {}: {error}", case.case_id))?;
        let pass = result.cm_pdk.pass && result.um_m_s.pass && result.xm_m.pass;
        cases.push(CaseReport {
            case_id: case.case_id,
            pdk_mg_m3: case.pdk_mg_m3,
            evidence: case.evidence,
            metrics: result,
            pass,
        });
    }
    let passed = cases.iter().filter(|c| c.pass).count();
    let summary = Summary {
        compared: cases.len(),
        passed,
        failed: cases.len() - passed,
        skipped: input.skipped.len(),
        all_passed: passed == cases.len(),
    };
    Ok(Report {
        schema_version: 1,
        scope: "individual_source_parameters_vs_saved_exports",
        limitations: [
            "Saved archive/project exports only; not live ERA execution or a complete calculation comparison.",
            "Provenance hashes are supplied by the extractor; this comparator does not open or verify source files.",
            "Cm is calculated in mg/m3 and divided by the supplied PDK in mg/m3; flat-terrain kernel assumptions apply.",
            "Pass uses an inclusive exact decimal half-step interval; displayed numeric errors use f64 arithmetic. Skipped cases are not validated.",
        ],
        provenance: input.provenance,
        summary,
        cases,
        skipped: input.skipped,
    })
}

fn read_input(reader: impl Read) -> Result<Input, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("Input exceeds 16 MiB".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn run(args: &[std::ffi::OsString]) -> Result<bool, String> {
    if args.len() != 3 {
        return Err("Usage: archive_source_compare INPUT.json NEW-REPORT.json".into());
    }
    let input = read_input(File::open(&args[1]).map_err(|e| e.to_string())?)?;
    let report = compare(input)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])
        .map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &report).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    Ok(report.summary.all_passed)
}
fn main() {
    match run(&std::env::args_os().collect::<Vec<_>>()) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("archive_source_compare: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture() -> Value {
        let source = PointSource {
            id: "synthetic".into(),
            x_m: 0.,
            y_m: 0.,
            height_m: 20.,
            outlet: era_engine::dispersion::Outlet::Circular { diameter_m: 1. },
            exit_velocity_m_s: 4.,
            gas_temperature_c: 100.,
            emission_g_s: 1.,
            settling_factor: 1.,
        };
        let p = source.parameters(160., 20.).unwrap();
        json!({"schema_version":1,"provenance":{"archive_name":"synthetic.era","archive_sha256":"a".repeat(64)},
            "cases":[{"case_id":"case-1","coefficient_a":160.,"air_temperature_c":20.,"pdk_mg_m3":0.2,
            "source":source,"expected":{"cm_pdk":format!("{:.8}", p.cm_mg_m3 / 0.2),
            "um_m_s":format!("{:.4}",p.um_m_s),"xm_m":format!("{:.3}",p.xm_m)},
            "evidence":[{"member":"synthetic-output.txt","sha256":"b".repeat(64)}]}],"skipped":[]})
    }
    fn checked(value: Value) -> Result<Report, String> {
        compare(serde_json::from_value(value).map_err(|e| e.to_string())?)
    }
    #[test]
    fn pass_and_unit_conversion() {
        let report = checked(fixture()).unwrap();
        assert!(report.summary.all_passed);
        assert_eq!(report.summary.compared, 1);
        assert!(report.cases[0].metrics.cm_pdk.absolute_error <= 0.000000005);
        let mut value = fixture();
        value["cases"][0]["pdk_mg_m3"] = json!(1.);
        let report = checked(value).unwrap();
        assert!(!report.summary.all_passed);
        assert!(!report.cases[0].metrics.cm_pdk.pass);
        assert!(report.cases[0].metrics.um_m_s.pass);
        assert!(report.cases[0].metrics.xm_m.pass);
    }
    #[test]
    fn mismatch_is_reported() {
        let mut value = fixture();
        value["cases"][0]["expected"]["xm_m"] = json!("0.000");
        let report = checked(value).unwrap();
        assert_eq!(report.summary.failed, 1);
        assert!(report.cases[0].metrics.xm_m.error > 0.);
    }
    #[test]
    fn bad_printed_values() {
        for s in [
            "",
            "-1",
            "+1",
            "1e2",
            "NaN",
            "inf",
            ".1",
            "1.",
            "1.2.3",
            " 1",
            "1 ",
            "١",
            "0.1234567890123",
        ] {
            assert!(printed(s).is_err(), "{s}");
        }
        assert!(printed(&"1".repeat(33)).is_err());
        for s in ["0", "001", "1.0", "0.123456789012", &"9".repeat(32)] {
            assert!(printed(s).is_ok(), "{s}");
        }
    }
    #[test]
    fn exact_rounding_boundaries() {
        assert!(metric(0.5, "1").unwrap().pass);
        assert!(metric(1.5, "1").unwrap().pass);
        assert!(
            !metric(f64::from_bits(1.5f64.to_bits() + 1), "1")
                .unwrap()
                .pass
        );
        assert!(
            !metric(f64::from_bits(0.5f64.to_bits() - 1), "1")
                .unwrap()
                .pass
        );
        assert!(metric(0., "0.000000000000").unwrap().pass);
        assert!(metric(f64::from_bits(1), "0.000000000000").unwrap().pass);
        // Naively parsing the expected value as f64 would incorrectly pass.
        assert!(!metric(9007199254740992., "9007199254740993").unwrap().pass);
        assert!(metric(9007199254740992., "9007199254740992").unwrap().pass);
        assert!(!metric(f64::MAX, "0").unwrap().pass);
        assert!(metric(f64::INFINITY, "0").is_err());
        assert!(metric(-1., "0").is_err());
    }
    #[test]
    fn invalid_pdk_and_kernel_inputs() {
        for pdk in [0., -1.] {
            let mut value = fixture();
            value["cases"][0]["pdk_mg_m3"] = json!(pdk);
            assert!(checked(value).unwrap_err().contains("pdk_mg_m3"));
        }
        let mut input: Input = serde_json::from_value(fixture()).unwrap();
        input.cases[0].pdk_mg_m3 = f64::NAN;
        assert!(compare(input).is_err());
        let mut value = fixture();
        value["cases"][0]["coefficient_a"] = json!(-1.);
        assert!(checked(value).is_err());
    }
    #[test]
    fn empty_budget_and_duplicate_ids() {
        let mut value = fixture();
        value["cases"] = json!([]);
        assert!(checked(value).is_err());
        let mut value = fixture();
        let case = value["cases"][0].clone();
        value["cases"] = json!([case, case]);
        assert!(checked(value).unwrap_err().contains("Duplicate"));
        let mut value = fixture();
        value["skipped"] = json!([{"case_id":"case-1","reason":"unsupported"}]);
        assert!(checked(value).unwrap_err().contains("Duplicate"));
        let mut value = fixture();
        value["cases"] = Value::Array(vec![value["cases"][0].clone(); MAX_CASES + 1]);
        assert!(checked(value).unwrap_err().contains("10000"));
        assert!(read_input(std::io::repeat(b' ').take(MAX_BYTES as u64 + 1))
            .unwrap_err()
            .contains("16 MiB"));
    }
    #[test]
    fn strict_schema_and_evidence() {
        for path in [
            vec![],
            vec!["provenance"],
            vec!["cases", "0"],
            vec!["cases", "0", "expected"],
            vec!["cases", "0", "source"],
            vec!["cases", "0", "evidence", "0"],
        ] {
            let mut value = fixture();
            let mut target = &mut value;
            for key in path {
                target = if key == "0" {
                    &mut target[0]
                } else {
                    &mut target[key]
                };
            }
            target["unknown"] = json!(true);
            assert!(checked(value).is_err());
        }
        let mut value = fixture();
        value["schema_version"] = json!(2);
        assert!(checked(value).is_err());
        let mut value = fixture();
        value["cases"][0]["evidence"] = json!([]);
        assert!(checked(value).is_err());
        let mut value = fixture();
        value["provenance"]["archive_sha256"] = json!("bad");
        assert!(checked(value).is_err());
    }
    #[test]
    fn project_provenance_is_explicit_and_strict() {
        let mut value = fixture();
        value["provenance"] = json!({"project_name":"synthetic-project",
            "selected_files_manifest_sha256":"c".repeat(64)});
        assert!(checked(value.clone()).unwrap().summary.all_passed);
        value["provenance"]["archive_name"] = json!("ambiguous.zip");
        assert!(checked(value).is_err());
    }
    #[test]
    fn skipped_cases_do_not_become_comparisons() {
        let mut value = fixture();
        value["skipped"] = json!([{"case_id":"case-2","reason":"unsupported synthetic input"}]);
        let report = checked(value).unwrap();
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.compared, 1);
        assert!(report.summary.all_passed);
        assert_eq!(report.skipped[0].case_id, "case-2");
    }
    #[test]
    fn cli_report_exclusive_create_and_bad_input() {
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = Temp(std::env::temp_dir().join(format!(
            "era-source-compare-test-{}-{nonce}",
            std::process::id()
        )));
        std::fs::create_dir(&temp.0).unwrap();
        let input = temp.0.join("synthetic.json");
        let output = temp.0.join("new-report.json");
        let args = vec![
            "archive_source_compare".into(),
            input.clone().into_os_string(),
            output.clone().into_os_string(),
        ];
        std::fs::write(&input, serde_json::to_vec(&fixture()).unwrap()).unwrap();
        assert!(run(&args).unwrap());
        let saved = std::fs::read(&output).unwrap();
        let report: Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(report["summary"]["all_passed"], true);
        assert!(run(&args).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), saved);
        let mut value = fixture();
        value["cases"][0]["expected"]["xm_m"] = json!("0.0");
        std::fs::write(&input, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut mismatch_args = args.clone();
        mismatch_args[2] = temp.0.join("mismatch.json").into_os_string();
        assert!(!run(&mismatch_args).unwrap());
        let mut invalid_args = args;
        let invalid_output = temp.0.join("invalid-report.json");
        invalid_args[2] = invalid_output.clone().into_os_string();
        std::fs::write(&input, b"{bad json}").unwrap();
        assert!(run(&invalid_args).is_err());
        assert!(!invalid_output.exists());
    }
}
