//! Numeric table ranges, distinct from subtraction expressions in the DSL.
use crate::Result;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NumericRange {
    pub min: f64,
    pub max: f64,
}
impl NumericRange {
    pub fn parse(raw: &str) -> Result<Self> {
        fn finite(s: &str) -> Option<f64> {
            s.trim().parse::<f64>().ok().filter(|v| v.is_finite())
        }
        let raw = raw.trim();
        if let Some(value) = finite(raw) {
            return Ok(Self {
                min: value,
                max: value,
            });
        }
        for (i, c) in raw.char_indices() {
            if i == 0 || !matches!(c, '-' | '–' | '—') {
                continue;
            }
            if let (Some(a), Some(b)) = (finite(&raw[..i]), finite(&raw[i + c.len_utf8()..])) {
                return Ok(Self {
                    min: a.min(b),
                    max: a.max(b),
                });
            }
        }
        Err(format!("Invalid or empty numeric range {raw:?}"))
    }
    pub fn interpolate(self, fraction: f64) -> Result<f64> {
        if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
            return Err("_Diap_ must be a finite number in 0..=1".into());
        }
        let value = self.min * (1. - fraction) + self.max * fraction;
        if !value.is_finite() {
            return Err("Non-finite range result".into());
        }
        Ok(value)
    }
    pub fn contains(self, value: f64) -> bool {
        value.is_finite() && self.min <= value && value <= self.max
    }
}
