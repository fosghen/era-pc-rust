pub mod data;
pub mod demo;
pub mod dispersion;
pub mod dispersion_compare;
pub mod dispersion_replay;
pub mod engine;
pub mod expr;
pub mod range;
pub mod wind_search;
pub type Result<T> = std::result::Result<T, String>;

/// Independent cases share read-only tables and compiled programs. Output order
/// matches input order; any failed case makes the batch return an error.
pub fn run_batch(
    db: &data::Database,
    scenarios: &[engine::Scenario],
    workers: usize,
) -> Result<Vec<engine::RunResult>> {
    use std::collections::BTreeMap;
    if workers == 0 || workers > 256 {
        return Err("workers must be in 1..=256".into());
    }
    if scenarios.is_empty() {
        return Ok(Vec::new());
    }
    let mut programs = BTreeMap::new();
    for scenario in scenarios {
        if !programs.contains_key(&scenario.method) {
            let rows = db
                .methods
                .get(&scenario.method)
                .ok_or_else(|| format!("Unknown method {}", scenario.method))?;
            programs.insert(
                scenario.method.clone(),
                engine::Program::compile(&scenario.method, rows)?,
            );
        }
    }
    let chunk_size = scenarios.len().div_ceil(workers.min(scenarios.len()));
    std::thread::scope(|scope| {
        let handles: Vec<_> = scenarios
            .chunks(chunk_size)
            .enumerate()
            .map(|(chunk_index, chunk)| {
                let programs = &programs;
                scope.spawn(move || -> Result<Vec<engine::RunResult>> {
                    chunk
                        .iter()
                        .enumerate()
                        .map(|(i, scenario)| {
                            engine::Runtime::new(db, scenario.clone())
                                .run(&programs[&scenario.method])
                                .map_err(|e| {
                                    format!("batch case {}: {e}", chunk_index * chunk_size + i)
                                })
                        })
                        .collect()
                })
            })
            .collect();
        let mut output = Vec::with_capacity(scenarios.len());
        for handle in handles {
            output.extend(handle.join().map_err(|_| "Calculation worker panicked")??);
        }
        Ok(output)
    })
}
