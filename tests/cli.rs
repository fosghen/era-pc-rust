use std::process::Command;

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_era-engine"))
        .env("ERA_DATA", "nonexistent-test-data-directory")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_and_version_do_not_load_local_data() {
    for args in [vec![], vec!["--help"], vec!["-h"], vec!["--version"]] {
        let output = cli(&args);
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn demo_runs_without_local_data() {
    let output = cli(&["demo"]);
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["method"], "DEMO");
    assert_eq!(result["variables"]["_g_"], 1.);
    assert_eq!(result["variables"]["_m_"], 3.6);
    assert_eq!(result["writes"].as_array().unwrap().len(), 2);
}

#[test]
fn dispersion_runs_without_local_data() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/dispersion.json");
    let output = cli(&["dispersion", path]);
    assert!(output.status.success(), "{:?}", output);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["receptors"].as_array().unwrap().len(), 5);
    assert!(result["source_parameters"][0]["cm_mg_m3"].as_f64().unwrap() > 0.);
    assert!(!result["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn wind_search_and_reference_comparison_are_standalone() {
    for (command, file, field) in [
        ("dispersion-search", "dispersion-search.json", "receptors"),
        (
            "dispersion-compare",
            "dispersion-reference.json",
            "differences",
        ),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(file);
        let output = cli(&[command, path.to_str().unwrap()]);
        assert!(output.status.success(), "{:?}", output);
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result[field].as_array().unwrap().len(), 2);
    }
}

#[test]
fn comparison_mismatch_returns_json_and_nonzero_exit() {
    let mut input: serde_json::Value =
        serde_json::from_str(include_str!("../examples/dispersion-reference.json")).unwrap();
    input["expected_receptors"][0]["concentrations_mg_m3"][0] = 0.into();
    let path =
        std::env::temp_dir().join(format!("era-compare-mismatch-{}.json", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    use std::io::Write;
    file.write_all(serde_json::to_string(&input).unwrap().as_bytes())
        .unwrap();
    drop(file);
    let output = cli(&["dispersion-compare", path.to_str().unwrap()]);
    std::fs::remove_file(&path).unwrap();
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["passed"], false);
    assert_eq!(result["failed"], 1);
}

#[test]
fn errors_are_actionable_without_panicking() {
    for args in [
        vec!["unknown"],
        vec!["run"],
        vec!["demo", "extra"],
        vec!["audit", "extra"],
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
        assert!(output.stdout.is_empty());
    }
    let output = cli(&["audit"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Set ERA_DATA"));
}
