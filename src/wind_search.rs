//! Deterministic, globally refined wind grids with additional source-axis seeds.
//! Convergence is an observed grid-stability test, NOT a certified global bound
//! and NOT a reconstruction of ERA's optimizer.
use crate::{
    dispersion::{self, Receptor, Request, SourceParameters, Wind},
    Result,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchOptions {
    pub initial_directions: usize,
    pub initial_speed_intervals: usize,
    pub max_refinements: usize,
    pub direction_tolerance_degrees: f64,
    pub speed_tolerance_m_s: f64,
    pub concentration_relative_tolerance: f64,
    pub concentration_absolute_tolerance_mg_m3: f64,
    /// Per receptor, including all sources, repeated grid points and seeds.
    pub max_source_evaluations_per_receptor: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchRequest {
    pub calculation: Request,
    pub search: SearchOptions,
}
#[derive(Clone, Debug, Serialize)]
pub struct SearchLevel {
    pub refinement: usize,
    pub direction_step_degrees: f64,
    pub speed_step_m_s: f64,
    pub best_concentration_mg_m3: f64,
    pub improvement_mg_m3: Option<f64>,
    pub cumulative_source_evaluations: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct SearchPoint {
    pub id: String,
    pub best_found_mg_m3: f64,
    pub wind: Wind,
    pub source_contributions_mg_m3: Vec<f64>,
    /// grid_stable, refinement_limit, or evaluation_budget; never a global certificate.
    pub status: String,
    pub history: Vec<SearchLevel>,
    pub source_evaluations: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct SearchResult {
    pub model: String,
    pub pollutant: String,
    pub settings: SearchOptions,
    pub source_parameters: Vec<SourceParameters>,
    pub receptors: Vec<SearchPoint>,
    pub warnings: Vec<String>,
}
impl SearchOptions {
    fn validate(&self, request: &Request) -> Result<()> {
        if !(4..=360).contains(&self.initial_directions)
            || !(1..=1000).contains(&self.initial_speed_intervals)
            || self.max_refinements > 10
        {
            return Err(
                "Search requires 4..=360 directions, 1..=1000 speed intervals, 0..=10 refinements"
                    .into(),
            );
        }
        for (name, value, max) in [
            (
                "direction_tolerance_degrees",
                self.direction_tolerance_degrees,
                90.,
            ),
            ("speed_tolerance_m_s", self.speed_tolerance_m_s, 330.),
            (
                "concentration_relative_tolerance",
                self.concentration_relative_tolerance,
                1.,
            ),
            (
                "concentration_absolute_tolerance_mg_m3",
                self.concentration_absolute_tolerance_mg_m3,
                f64::MAX,
            ),
        ] {
            if !value.is_finite() || value < 0. || value > max {
                return Err(format!("Invalid {name}"));
            }
        }
        if self.direction_tolerance_degrees == 0. || self.speed_tolerance_m_s == 0. {
            return Err("Wind resolution tolerances must be positive".into());
        }
        let budget = self
            .max_source_evaluations_per_receptor
            .checked_mul(request.receptors.len());
        if self.max_source_evaluations_per_receptor == 0 || budget.is_none_or(|n| n > 20_000_000) {
            return Err(
                "Search budgets must be positive and total at most 20 million source evaluations"
                    .into(),
            );
        }
        Ok(())
    }
}
fn unique(values: &mut Vec<f64>) {
    values.sort_by(f64::total_cmp);
    values.dedup();
}
struct Evaluator<'a> {
    request: &'a Request,
    params: &'a [SourceParameters],
    point: &'a Receptor,
    best: Option<(f64, Wind, Vec<f64>)>,
    evaluations: usize,
    scratch: Vec<f64>,
}
impl Evaluator<'_> {
    fn evaluate(&mut self, wind: Wind) -> Result<()> {
        self.scratch.clear();
        for (p, s) in self.params.iter().zip(&self.request.sources) {
            self.scratch.push(p.concentration(s, self.point, wind)?);
        }
        self.evaluations += self.params.len();
        let total: f64 = self.scratch.iter().sum();
        if !total.is_finite() {
            return Err("Nonfinite total concentration".into());
        }
        if self.best.as_ref().is_none_or(|best| total > best.0) {
            self.best = Some((total, wind, self.scratch.clone()));
        }
        Ok(())
    }
}
pub fn search(input: &SearchRequest) -> Result<SearchResult> {
    let request = &input.calculation;
    let settings = &input.search;
    settings.validate(request)?;
    let params = dispersion::validate(request, true)?;
    let mut receptors = Vec::new();
    for point in &request.receptors {
        let mut evaluator = Evaluator {
            request,
            params: &params,
            point,
            best: None,
            evaluations: 0,
            scratch: Vec::with_capacity(params.len()),
        };
        let mut bearing_seeds = Vec::new();
        let mut speed_seeds = vec![0.5, request.max_wind_speed_m_s, 5.];
        for (source, p) in request.sources.iter().zip(&params) {
            let dx = source.x_m - point.x_m;
            let dy = source.y_m - point.y_m;
            if dx != 0. || dy != 0. {
                bearing_seeds.push(dx.atan2(dy).to_degrees().rem_euclid(360.));
            }
            for u in [p.um_m_s, 0.25 * p.um_m_s] {
                speed_seeds.push(u.clamp(0.5, request.max_wind_speed_m_s));
            }
        }
        // User-specified winds are included as exact pairs, not a Cartesian product.
        let seed_work = request
            .winds
            .len()
            .checked_mul(params.len())
            .ok_or("Search size overflow")?;
        if seed_work > settings.max_source_evaluations_per_receptor {
            return Err("Wind seeds exceed per-receptor evaluation budget".into());
        }
        for wind in &request.winds {
            evaluator.evaluate(*wind)?;
        }
        let mut history: Vec<SearchLevel> = Vec::new();
        let mut status = "refinement_limit";
        let mut stable_levels = 0;
        for level in 0..=settings.max_refinements {
            let directions = settings.initial_directions * (1 << level);
            let intervals = settings.initial_speed_intervals * (1 << level);
            let angle_step = 360. / directions as f64;
            let speed_step = (request.max_wind_speed_m_s - 0.5) / intervals as f64;
            // Check the base grid before allocating potentially large vectors.
            let base_work = directions
                .checked_mul(intervals + 1)
                .and_then(|n| n.checked_mul(params.len()));
            let remaining = settings.max_source_evaluations_per_receptor - evaluator.evaluations;
            if base_work.is_none_or(|n| n > remaining) {
                status = "evaluation_budget";
                break;
            }
            let mut angles = bearing_seeds.clone();
            angles.extend((0..directions).map(|i| 360. * i as f64 / directions as f64));
            unique(&mut angles);
            let mut speeds = speed_seeds.clone();
            speeds.extend(
                (0..=intervals).map(|i| {
                    0.5 + (request.max_wind_speed_m_s - 0.5) * (i as f64 / intervals as f64)
                }),
            );
            unique(&mut speeds);
            let work = angles
                .len()
                .checked_mul(speeds.len())
                .and_then(|n| n.checked_mul(params.len()));
            if work.is_none_or(|n| n > remaining) {
                status = "evaluation_budget";
                break;
            }
            for angle in angles {
                for &speed in &speeds {
                    evaluator.evaluate(Wind {
                        from_degrees: angle,
                        speed_m_s: speed,
                    })?;
                }
            }
            let best = evaluator
                .best
                .as_ref()
                .ok_or("Search produced no candidate")?
                .0;
            let improvement = history
                .last()
                .map(|previous| (best - previous.best_concentration_mg_m3).max(0.));
            if improvement.is_some_and(|delta| {
                delta
                    <= settings.concentration_absolute_tolerance_mg_m3
                        + settings.concentration_relative_tolerance * best.abs()
            }) {
                stable_levels += 1;
            } else {
                stable_levels = 0;
            }
            history.push(SearchLevel {
                refinement: level,
                direction_step_degrees: angle_step,
                speed_step_m_s: speed_step,
                best_concentration_mg_m3: best,
                improvement_mg_m3: improvement,
                cumulative_source_evaluations: evaluator.evaluations,
            });
            if stable_levels >= 2
                && angle_step <= settings.direction_tolerance_degrees
                && speed_step <= settings.speed_tolerance_m_s
            {
                status = "grid_stable";
                break;
            }
        }
        if history.is_empty() {
            return Err(format!(
                "Receptor {}: budget too small to complete the initial search grid",
                point.id
            ));
        }
        let (best, wind, contributions) = evaluator.best.ok_or("Search produced no candidate")?;
        receptors.push(SearchPoint {
            id: point.id.clone(),
            best_found_mg_m3: best,
            wind,
            source_contributions_mg_m3: contributions,
            status: status.into(),
            history,
            source_evaluations: evaluator.evaluations,
        });
    }
    Ok(SearchResult {
        model: "MRR-2017 point sources; independent refined-grid wind search".into(),
        pollutant: request.pollutant.clone(), settings: settings.clone(), source_parameters: params, receptors,
        warnings: vec![
            "Best found is a lower bound on the modeled maximum, not a certified continuous global maximum.".into(),
            "grid_stable means two small improvements plus requested grid spacing; narrow peaks may remain unresolved.".into(),
            "Independent algorithm, not validated against ERA; only the documented point-source subset is supported.".into(),
            "Each receptor has its own worst wind; these maxima are not a simultaneous concentration field.".into(),
        ],
    })
}
