//! Pair each receptor with one wind, without an N-by-N Cartesian product.
//! This shares the production kernel and is a replay, not a second oracle.
use crate::{
    dispersion::{self, Request, SourceParameters, Wind},
    Result,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ReplayPoint {
    pub id: String,
    pub wind: Wind,
    pub concentration_mg_m3: f64,
}

#[derive(Debug, Serialize)]
pub struct ReplayResult {
    pub scope: String,
    pub pollutant: String,
    pub source_evaluations: usize,
    pub source_parameters: Vec<SourceParameters>,
    pub points: Vec<ReplayPoint>,
    pub warnings: Vec<String>,
}

pub fn replay(request: &Request) -> Result<ReplayResult> {
    if request.receptors.len() != request.winds.len() {
        return Err("Paired replay requires one wind per receptor, in matching order".into());
    }
    let work = request
        .sources
        .len()
        .checked_mul(request.receptors.len())
        .ok_or("Replay evaluation count overflow")?;
    if work > 20_000_000 {
        return Err("Replay exceeds 20 million source-point evaluations".into());
    }
    let params = dispersion::validate(request, false)?;
    let mut points = Vec::with_capacity(request.receptors.len());
    for (point, wind) in request.receptors.iter().zip(&request.winds) {
        let mut total = 0.;
        for (source, parameter) in request.sources.iter().zip(&params) {
            total += parameter.concentration(source, point, *wind)?;
        }
        if !total.is_finite() {
            return Err("Nonfinite total concentration".into());
        }
        points.push(ReplayPoint {
            id: point.id.clone(),
            wind: *wind,
            concentration_mg_m3: total,
        });
    }
    Ok(ReplayResult {
        scope: "paired_fixed_wind_replay_not_optimizer_validation".into(),
        pollutant: request.pollutant.clone(),
        source_evaluations: work,
        source_parameters: params,
        points,
        warnings: vec![
            "Each receptor uses only its corresponding supplied wind.".into(),
            "Same limited point-source kernel as dispersion; not an independent numerical oracle."
                .into(),
            "No coordinate conversion, expected-value fitting or tolerance applied.".into(),
            "Only ground-level 2 m receptors, flat terrain; no buildings or background.".into(),
        ],
    })
}
