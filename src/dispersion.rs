//! Experimental MRR-2017 point-source kernel, independently implemented from
//! chapter V (3–29) and VIII (49), not decompiled from ERA binaries.
//! Flat terrain, vertical circular/rectangular outlet, constant emission,
//! one pollutant, ground-level receptors, explicitly supplied wind samples.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, f64::consts::PI};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "shape", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outlet {
    Circular { diameter_m: f64 },
    Rectangular { length_m: f64, width_m: f64 },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PointSource {
    pub id: String,
    pub x_m: f64,
    pub y_m: f64,
    pub height_m: f64,
    pub outlet: Outlet,
    pub exit_velocity_m_s: f64,
    pub gas_temperature_c: f64,
    pub emission_g_s: f64,
    pub settling_factor: f64,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Wind {
    /// Meteorological direction FROM, clockwise from north; x east, y north.
    pub from_degrees: f64,
    pub speed_m_s: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receptor {
    pub id: String,
    pub x_m: f64,
    pub y_m: f64,
    /// Only the standard ground-level two-metre layer is supported.
    pub height_m: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub pollutant: String,
    pub coefficient_a: f64,
    pub air_temperature_c: f64,
    pub max_wind_speed_m_s: f64,
    pub sources: Vec<PointSource>,
    pub receptors: Vec<Receptor>,
    pub winds: Vec<Wind>,
}
#[derive(Clone, Debug, Serialize)]
pub struct SourceParameters {
    pub id: String,
    pub effective_height_m: f64,
    pub effective_diameter_m: f64,
    pub effective_volume_m3_s: f64,
    pub delta_temperature_c: f64,
    pub f: Option<f64>,
    pub f_e: f64,
    pub v_m: f64,
    pub v_m_prime: f64,
    pub m: Option<f64>,
    pub n: Option<f64>,
    pub regime: String,
    /// Unconstrained individual-source maximum, not a sum or grid maximum.
    pub cm_mg_m3: f64,
    pub xm_m: f64,
    pub um_m_s: f64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReceptorResult {
    pub id: String,
    /// In the same order as the request's winds.
    pub concentrations_mg_m3: Vec<f64>,
    pub sampled_max_mg_m3: f64,
    pub worst_sample_index: usize,
    pub worst_sample_wind: Wind,
    /// Source contributions at this receptor's worst supplied wind sample.
    pub contributions_at_worst_mg_m3: Vec<f64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DispersionResult {
    pub model: String,
    pub pollutant: String,
    pub source_parameters: Vec<SourceParameters>,
    pub receptors: Vec<ReceptorResult>,
    pub warnings: Vec<String>,
}
fn finite(name: &str, x: f64) -> Result<f64> {
    if x.is_finite() {
        Ok(x)
    } else {
        Err(format!("{name} must be finite"))
    }
}
fn positive(name: &str, x: f64) -> Result<f64> {
    finite(name, x)?;
    if x > 0. {
        Ok(x)
    } else {
        Err(format!("{name} must be positive"))
    }
}
fn bounded(name: &str, x: f64, min: f64, max: f64) -> Result<f64> {
    finite(name, x)?;
    if (min..=max).contains(&x) {
        Ok(x)
    } else {
        Err(format!("{name} must be in {min}..={max}"))
    }
}
fn n_coefficient(v: f64) -> f64 {
    if v < 0.5 {
        4.4 * v
    } else if v < 2. {
        0.532 * v * v - 2.13 * v + 3.13
    } else {
        1.
    }
}
impl PointSource {
    pub fn parameters(&self, a: f64, air_c: f64) -> Result<SourceParameters> {
        positive("coefficient_a", a)?;
        bounded(
            "air_temperature_c",
            air_c,
            -273.15 + f64::EPSILON * 1024.,
            3000.,
        )?;
        if self.id.trim().is_empty() {
            return Err("Source id must not be empty".into());
        }
        finite("source x_m", self.x_m)?;
        finite("source y_m", self.y_m)?;
        bounded("height_m", self.height_m, 0., 100_000.)?;
        let h = self.height_m.max(2.); // §4.4
        let w = positive(
            "exit_velocity_m_s (zero-flow sources not implemented)",
            self.exit_velocity_m_s,
        )?;
        if w > 330. {
            return Err("Exit velocity >330 m/s requires chapter XII (not implemented)".into());
        }
        bounded(
            "gas_temperature_c",
            self.gas_temperature_c,
            -273.15 + f64::EPSILON * 1024.,
            3000.,
        )?;
        let dt = self.gas_temperature_c - air_c;
        if dt < 0. {
            return Err(
                "Negative temperature difference / fixed-height sources not implemented".into(),
            );
        }
        finite("emission_g_s", self.emission_g_s)?;
        if self.emission_g_s < 0. {
            return Err("emission_g_s must be nonnegative".into());
        }
        let settling = bounded("settling_factor", self.settling_factor, 1., 3.)?;
        let diameter = match self.outlet {
            Outlet::Circular { diameter_m } => positive("diameter_m", diameter_m)?,
            Outlet::Rectangular { length_m, width_m } => {
                positive("length_m", length_m)?;
                positive("width_m", width_m)?;
                2. * length_m * width_m / (length_m + width_m) // (32)
            }
        };
        positive("effective diameter", diameter)?;
        let volume = positive("effective volume", PI * diameter.powi(2) * w / 4.)?; // (4), (33)
        let vm = finite("v_m", 0.65 * (volume * dt / h).cbrt())?; // (5)
        let vp = positive("v_m_prime", 1.3 * w * diameter / h)?; // (6)
        let fe = finite("f_e", 800. * vp.powi(3))?; // (8)
        let f = if dt > 0. {
            Some(finite(
                "f",
                1000. * w.powi(2) * diameter / (h.powi(2) * dt),
            )?)
        } else {
            None
        };
        let cold = dt < 0.5 || f.is_some_and(|f| f >= 100.);
        let factor = finite("A*M*F", a * self.emission_g_s * settling)?; // eta=1, flat terrain only
        let (cm, distance_factor, um, m, n, regime) = if cold {
            let (cm, n, regime) = if vp < 0.5 {
                (factor * 0.9 / h.powf(7. / 3.), None, "cold_low_wind_13_14b")
            } else {
                let n = n_coefficient(vp);
                (
                    factor * n * diameter / (8. * volume * h.powf(4. / 3.)),
                    Some(n),
                    "cold_11",
                )
            };
            let d = if vp <= 0.5 {
                5.7
            } else if vp <= 2. {
                11.4 * vp
            } else {
                16. * vp.sqrt()
            }; // (17)
            let um = if vp <= 0.5 {
                0.5
            } else if vp <= 2. {
                vp
            } else {
                2.2 * vp
            }; // (19)
            (cm, d, um, None, n, regime)
        } else {
            let f = f.ok_or("Missing warm-source f")?;
            let fm = if fe < f { fe } else { f }; // §5.7: substitute ONLY in m
            let m = 1. / (0.67 + 0.1 * fm.sqrt() + 0.34 * fm.cbrt()); // (9a)
            let (cm, n, regime) = if vm < 0.5 {
                (
                    factor * 2.86 * m / h.powf(7. / 3.),
                    None,
                    "warm_low_wind_13_14a",
                )
            } else {
                let n = n_coefficient(vm);
                (
                    factor * m * n / (h.powi(2) * (volume * dt).cbrt()),
                    Some(n),
                    "warm_3",
                )
            };
            let d = if vm <= 0.5 {
                2.48 * (1. + 0.28 * fe.cbrt())
            } else if vm <= 2. {
                4.95 * vm * (1. + 0.28 * f.cbrt())
            } else {
                7. * vm.sqrt() * (1. + 0.28 * f.cbrt())
            }; // (16)
            let um = if vm <= 0.5 {
                0.5
            } else if vm <= 2. {
                vm
            } else {
                vm * (1. + 0.12 * f.sqrt())
            }; // (18)
            (cm, d, um, Some(m), n, regime)
        };
        finite("cm", cm)?;
        let xm = positive("xm", (5. - settling) * distance_factor * h / 4.)?; // (15)
        positive("um", um)?;
        Ok(SourceParameters {
            id: self.id.clone(),
            effective_height_m: h,
            effective_diameter_m: diameter,
            effective_volume_m3_s: volume,
            delta_temperature_c: dt,
            f,
            f_e: fe,
            v_m: vm,
            v_m_prime: vp,
            m,
            n,
            regime: regime.into(),
            cm_mg_m3: cm,
            xm_m: xm,
            um_m_s: um,
        })
    }
}
/// (21), (23). These are not an optimizer over meteorological conditions.
fn wind_factors(ratio: f64) -> (f64, f64) {
    let r = if ratio <= 1. {
        0.67 * ratio + 1.67 * ratio.powi(2) - 1.34 * ratio.powi(3)
    } else {
        3. * ratio / (2. * ratio.powi(2) - ratio + 2.)
    };
    let p = if ratio <= 0.25 {
        3.
    } else if ratio <= 1. {
        8.43 * (1. - ratio).powi(5) + 1.
    } else {
        0.32 * ratio + 0.68
    };
    (r, p)
}
fn axial_factor(q: f64, settling: f64, height: f64) -> f64 {
    let s = if q <= 1. {
        3. * q.powi(4) - 8. * q.powi(3) + 6. * q.powi(2)
    } else if q <= 8. {
        1.13 / (0.13 * q * q + 1.)
    } else if q <= 100. && settling <= 1.5 {
        q / (3.556 * q * q - 35.2 * q + 120.)
    } else if q <= 100. {
        1. / (0.1 * q * q + 2.456 * q - 17.8)
    } else if settling <= 1.5 {
        144.3 * q.powf(-7. / 3.)
    } else {
        37.76 * q.powf(-7. / 3.)
    }; // (25)
    if height < 10. && q < 1. {
        0.125 * (10. - height) + 0.125 * (height - 2.) * s
    } else {
        s
    } // (26)
}
impl SourceParameters {
    fn concentration(&self, source: &PointSource, point: &Receptor, wind: Wind) -> Result<f64> {
        let dx = finite("receptor offset x", point.x_m - source.x_m)?;
        let dy = finite("receptor offset y", point.y_m - source.y_m)?;
        if dx.hypot(dy) > 100_000. {
            return Err("Receptor is more than 100 km from a source".into());
        }
        let (sin, cos) = wind.from_degrees.to_radians().sin_cos();
        let x = -(dx * sin + dy * cos);
        let y = dx * cos - dy * sin;
        if x <= 0. {
            return Ok(0.);
        } // §8.1: only upwind sources contribute
        let (r, p) = wind_factors(wind.speed_m_s / self.um_m_s);
        let s1 = axial_factor(
            x / (p * self.xm_m),
            source.settling_factor,
            self.effective_height_m,
        );
        let ty = wind.speed_m_s.min(5.) * (y / x).powi(2); // (29)
                                                           // Infinite ty is the limiting zero concentration at extreme lateral distance.
        let s2 = if ty.is_infinite() {
            0.
        } else {
            (1. + 5. * ty + 12.8 * ty.powi(2) + 17. * ty.powi(3) + 45.1 * ty.powi(4)).powi(-2)
        }; // (28)
        let c = finite("concentration", self.cm_mg_m3 * r * s1 * s2)?;
        if c < 0. {
            return Err("Negative calculated concentration".into());
        }
        Ok(c)
    }
}

pub fn calculate(request: &Request) -> Result<DispersionResult> {
    if request.pollutant.trim().is_empty() {
        return Err("pollutant must not be empty".into());
    }
    bounded("max_wind_speed_m_s", request.max_wind_speed_m_s, 6., 330.)?;
    if request.sources.is_empty() || request.receptors.is_empty() || request.winds.is_empty() {
        return Err("sources, receptors and winds must not be empty".into());
    }
    let work = request
        .sources
        .len()
        .checked_mul(request.receptors.len())
        .and_then(|n| n.checked_mul(request.winds.len()));
    if work.is_none_or(|n| n > 20_000_000) {
        return Err("Request exceeds 20 million source-point-wind evaluations".into());
    }
    let mut ids = BTreeSet::new();
    let mut params = Vec::new();
    for source in &request.sources {
        if !ids.insert(&source.id) {
            return Err("Duplicate source id".into());
        }
        params.push(
            source
                .parameters(request.coefficient_a, request.air_temperature_c)
                .map_err(|e| format!("source {}: {e}", source.id))?,
        );
    }
    for wind in &request.winds {
        bounded("wind from_degrees", wind.from_degrees, 0., 360.)?;
        bounded(
            "wind speed_m_s",
            wind.speed_m_s,
            0.5,
            request.max_wind_speed_m_s,
        )?;
    }
    let mut receptors = Vec::new();
    ids.clear();
    for point in &request.receptors {
        if point.id.trim().is_empty() || !ids.insert(&point.id) {
            return Err("Empty or duplicate receptor id".into());
        }
        finite("receptor x_m", point.x_m)?;
        finite("receptor y_m", point.y_m)?;
        if point.height_m != 2. {
            return Err("Only ground-level receptors (height_m=2) implemented".into());
        }
        let mut concentrations = Vec::new();
        let mut best = 0;
        let mut contributions = Vec::new();
        for (index, wind) in request.winds.iter().enumerate() {
            let values = params
                .iter()
                .zip(&request.sources)
                .map(|(p, s)| p.concentration(s, point, *wind))
                .collect::<Result<Vec<_>>>()?;
            let total = finite("total concentration", values.iter().sum())?; // (49)
            if index == 0 || total > concentrations[best] {
                best = index;
                contributions = values;
            }
            concentrations.push(total);
        }
        receptors.push(ReceptorResult {
            id: point.id.clone(),
            sampled_max_mg_m3: concentrations[best],
            concentrations_mg_m3: concentrations,
            worst_sample_index: best,
            worst_sample_wind: request.winds[best],
            contributions_at_worst_mg_m3: contributions,
        });
    }
    Ok(DispersionResult { model: "MRR-2017 experimental point sources, flat terrain".into(),
        pollutant: request.pollutant.clone(), source_parameters: params, receptors,
        warnings: vec![
            "Independent implementation of a limited documented subset; not validated against ERA.EXE.".into(),
            "Maximum is over supplied wind samples only, not a continuous worst-case search.".into(),
            "No buildings, complex terrain, background, transformation, annual means, line/area sources or elevated receptors.".into(),
            "User must provide applicable climate coefficient A, F and mutually possible source operating conditions.".into(),
        ] })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn close(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-12, "{a} != {b}");
    }
    #[test]
    fn axial_branches_and_height_correction() {
        close(axial_factor(0.5, 1., 30.), 0.6875);
        close(axial_factor(1., 1., 30.), 1.);
        close(axial_factor(8., 1., 30.), 1.13 / 9.32);
        for q in [9., 100.] {
            close(
                axial_factor(q, 1.5, 30.),
                q / (3.556 * q * q - 35.2 * q + 120.),
            );
            close(
                axial_factor(q, 2., 30.),
                1. / (0.1 * q * q + 2.456 * q - 17.8),
            );
        }
        close(axial_factor(101., 1., 30.), 144.3 * 101_f64.powf(-7. / 3.));
        close(axial_factor(101., 2., 30.), 37.76 * 101_f64.powf(-7. / 3.));
        close(axial_factor(0.5, 1., 2.), 1.);
        close(axial_factor(0.5, 1., 6.), 0.5 + 0.5 * 0.6875);
        close(axial_factor(0.5, 1., 10.), 0.6875);
    }
    #[test]
    fn wind_correction_branches() {
        for t in [0.1_f64, 0.25, 0.5, 1., 2.] {
            let (r, p) = wind_factors(t);
            let expected_r = if t <= 1. {
                0.67 * t + 1.67 * t * t - 1.34 * t * t * t
            } else {
                3. * t / (2. * t * t - t + 2.)
            };
            let expected_p = if t <= 0.25 {
                3.
            } else if t <= 1. {
                8.43 * (1. - t).powi(5) + 1.
            } else {
                0.32 * t + 0.68
            };
            close(r, expected_r);
            close(p, expected_p);
        }
        close(wind_factors(1.).0, 1.);
        close(wind_factors(1.).1, 1.);
    }
    #[test]
    fn n_piecewise_boundaries() {
        close(n_coefficient(0.1), 0.44);
        close(n_coefficient(0.5), 2.198);
        close(n_coefficient(2.), 1.);
    }
}
