//! Research CLI: bounded JSON input, paired fixed winds, exclusive new output.
use era_engine::{dispersion::Request, dispersion_replay, Result};
use std::{
    env,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

fn run(input: &Path, output: &Path) -> Result<()> {
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut bytes = Vec::new();
    File::open(input)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("Replay input exceeds 16 MiB".into());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let result = dispersion_replay::replay(&request)?;
    let encoded = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    file.write_all(&encoded).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())
}

fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let result = if args.len() == 2 {
        run(Path::new(&args[0]), Path::new(&args[1]))
    } else {
        Err("Usage: field_replay request.json new-result.json".into())
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_preserves_inputs_and_rejects_bad_or_oversized_requests() {
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
        let temp = Temp(env::temp_dir().join(format!(
            "era-field-replay-test-{}-{nonce}",
            std::process::id()
        )));
        std::fs::create_dir(&temp.0).unwrap();
        let input = temp.0.join("request.json");
        let output = temp.0.join("result.json");
        let mut request: Request = serde_json::from_str(include_str!("dispersion.json")).unwrap();
        request.receptors.truncate(1);
        request.winds.truncate(1);
        let bytes = serde_json::to_vec(&request).unwrap();
        std::fs::write(&input, &bytes).unwrap();
        run(&input, &output).unwrap();
        let before = std::fs::read(&output).unwrap();
        assert!(run(&input, &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), before);
        assert!(run(&input, &input).is_err());
        assert_eq!(std::fs::read(&input).unwrap(), bytes);
        let invalid_output = temp.0.join("must-not-exist.json");
        request.winds.clear();
        std::fs::write(&input, serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(run(&input, &invalid_output).is_err());
        assert!(!invalid_output.exists());
        std::fs::write(&input, b"{\"unknown\": true}").unwrap();
        assert!(run(&input, &invalid_output).is_err());
        let file = File::create(&input).unwrap();
        file.set_len(16 * 1024 * 1024 + 1).unwrap();
        assert!(run(&input, &invalid_output).unwrap_err().contains("16 MiB"));
        assert!(!invalid_output.exists());
    }
}
