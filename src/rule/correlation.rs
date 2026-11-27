use std::collections::{HashMap, HashSet};
use std::fmt;

use anyhow::{Result, ensure};
use chrono::TimeDelta;
use serde::Deserialize;
use serde_yaml::Value as Yaml;

use super::sigma::Metadata;

/// Distinguishes invalid correlation input from ordinary unsupported Sigma files
/// when loading mixed rule directories.
#[derive(Debug)]
pub struct CorrelationError(pub(crate) String);

impl fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CorrelationError {}

#[derive(Clone, Debug)]
pub struct Rule {
    pub metadata: Metadata,
    pub rules: Vec<String>,
    pub group_by: Vec<String>,
    pub aliases: HashMap<String, HashMap<String, String>>,
    pub span: TimeDelta,
    pub kind: Kind,
    pub generate: bool,
}

#[derive(Clone, Debug)]
pub enum Kind {
    Temporal {
        minimum: usize,
    },
    Ordered,
    ValueCount {
        field: String,
        bounds: Vec<(Comparison, usize)>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Comparison {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl Comparison {
    pub(crate) fn test(self, n: usize, k: usize) -> bool {
        match self {
            Self::Eq => n == k,
            Self::Neq => n != k,
            Self::Gt => n > k,
            Self::Gte => n >= k,
            Self::Lt => n < k,
            Self::Lte => n <= k,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Definition {
    #[serde(rename = "type")]
    kind: String,
    #[serde(deserialize_with = "references")]
    rules: Vec<String>,
    #[serde(default)]
    group_by: Vec<String>,
    #[serde(default)]
    aliases: HashMap<String, HashMap<String, String>>,
    timespan: String,
    condition: Option<serde_yaml::Mapping>,
    #[serde(default)]
    generate: bool,
}

fn references<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Names {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Names::deserialize(d)? {
        Names::One(s) => vec![s],
        Names::Many(v) => v,
    })
}

impl Rule {
    pub(crate) fn parse(metadata: Metadata, definition: Yaml, generate: bool) -> Result<Self> {
        let input: Definition = serde_yaml::from_value(definition)?;
        ensure!(!input.rules.is_empty(), "missing rule references");
        ensure!(
            input.rules.iter().all(|s| !s.trim().is_empty()),
            "empty rule reference"
        );
        ensure!(
            input.rules.iter().collect::<HashSet<_>>().len() == input.rules.len(),
            "duplicate rule references"
        );
        ensure!(
            input.group_by.iter().all(|s| !s.trim().is_empty()),
            "empty group-by field"
        );
        let unit = input
            .timespan
            .chars()
            .last()
            .ok_or_else(|| anyhow!("empty timespan"))?;
        let scale = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => bail!(
                "invalid timespan '{}': expected s, m, h or d",
                input.timespan
            ),
        };
        let digits = &input.timespan[..input.timespan.len() - 1];
        let span = digits
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.checked_mul(scale))
            .and_then(|s| i64::try_from(s).ok())
            .and_then(TimeDelta::try_seconds)
            .ok_or_else(|| anyhow!("invalid timespan '{}'", input.timespan))?;
        let kind = match input.kind.as_str() {
            "temporal" => {
                let minimum = if let Some(condition) = input.condition {
                    ensure!(
                        condition.len() == 1,
                        "temporal requires exactly one lower bound"
                    );
                    let (op, n) = condition.into_iter().next().unwrap();
                    let threshold: usize = serde_yaml::from_value(n)?;
                    match op.as_str() {
                        Some("gte") => threshold,
                        Some("gt") => threshold
                            .checked_add(1)
                            .ok_or_else(|| anyhow!("temporal count overflow"))?,
                        _ => bail!("temporal count supports gt and gte"),
                    }
                } else {
                    input.rules.len()
                };
                ensure!(
                    minimum > 0 && minimum <= input.rules.len(),
                    "temporal count outside referenced rule range"
                );
                Kind::Temporal { minimum }
            }
            "temporal_ordered" => {
                ensure!(
                    input.condition.is_none(),
                    "explicit temporal_ordered count conditions are unsupported"
                );
                Kind::Ordered
            }
            "value_count" => {
                let mut condition = input
                    .condition
                    .ok_or_else(|| anyhow!("value_count requires a condition"))?;
                let field = condition
                    .remove("field")
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .filter(|f| !f.trim().is_empty())
                    .ok_or_else(|| anyhow!("value_count requires condition.field"))?;
                ensure!(
                    !condition.is_empty(),
                    "value_count requires a count comparison"
                );
                let bounds = condition
                    .into_iter()
                    .map(|(op, n)| {
                        Ok((
                            serde_yaml::from_value::<Comparison>(op)?,
                            serde_yaml::from_value::<usize>(n)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Kind::ValueCount { field, bounds }
            }
            _ => bail!("unsupported Sigma correlation type '{}'", input.kind),
        };
        for (alias, components) in &input.aliases {
            ensure!(
                input.group_by.contains(alias),
                "alias '{}' is not in group-by",
                alias
            );
            ensure!(
                input
                    .rules
                    .iter()
                    .all(|r| components.get(r).is_some_and(|s| !s.is_empty())),
                "alias '{}' must map each referenced rule to a field",
                alias
            );
            ensure!(
                components.keys().all(|r| input.rules.contains(r)),
                "unknown rule in alias '{}'",
                alias
            );
        }
        Ok(Self {
            aliases: input.aliases,
            metadata,
            rules: input.rules,
            group_by: input.group_by,
            span,
            kind,
            generate: generate || input.generate,
        })
    }
}
