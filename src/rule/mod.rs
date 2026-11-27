use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tau_engine::{
    Document,
    core::{
        Detection, optimiser,
        parser::{Expression, Pattern},
    },
};

use crate::file::Kind as FileKind;

pub use self::chainsaw::Rule as Chainsaw;
pub use self::sigma::Rule as Sigma;

pub mod chainsaw;
pub mod correlation;
pub use correlation::CorrelationError;
pub mod sigma;

#[derive(Clone, Debug)]
pub enum Rule {
    Chainsaw(Chainsaw),
    Sigma(Sigma),
    Correlation(correlation::Rule),
}

impl Rule {
    pub(crate) fn sigma_metadata(&self) -> Option<&sigma::Metadata> {
        match self {
            Self::Sigma(s) => Some(&s.metadata),
            Self::Correlation(c) => Some(&c.metadata),
            Self::Chainsaw(_) => None,
        }
    }

    pub(crate) fn authors(&self) -> &Vec<String> {
        match self {
            Self::Chainsaw(c) => &c.authors,
            Self::Sigma(s) => &s.authors,
            Self::Correlation(c) => &c.metadata.authors,
        }
    }

    #[inline]
    pub fn aggregate(&self) -> &Option<Aggregate> {
        match self {
            Self::Chainsaw(c) => &c.aggregate,
            Self::Sigma(s) => &s.aggregate,
            Self::Correlation(_) => &None,
        }
    }

    #[inline]
    pub fn is_kind(&self, kind: &Kind) -> bool {
        match self {
            Self::Chainsaw(_) => kind == &Kind::Chainsaw,
            Self::Sigma(_) | Self::Correlation(_) => kind == &Kind::Sigma,
        }
    }

    #[inline]
    pub fn level(&self) -> &Level {
        match self {
            Self::Chainsaw(c) => &c.level,
            Self::Sigma(s) => &s.level,
            Self::Correlation(c) => &c.metadata.level,
        }
    }

    #[inline]
    pub fn types(&self) -> &FileKind {
        match self {
            Self::Chainsaw(c) => &c.kind,
            Self::Sigma(_) | Self::Correlation(_) => &FileKind::Unknown,
        }
    }

    #[inline]
    pub fn name(&self) -> &String {
        match self {
            Self::Chainsaw(c) => &c.name,
            Self::Sigma(s) => &s.name,
            Self::Correlation(c) => &c.metadata.name,
        }
    }

    #[inline]
    pub fn solve(&self, document: &dyn Document) -> bool {
        match self {
            Self::Chainsaw(c) => match &c.filter {
                Filter::Detection(detection) => tau_engine::solve(detection, document),
                Filter::Expression(expression) => tau_engine::core::solve(expression, document),
            },
            Self::Sigma(s) => tau_engine::solve(&s.tau.detection, document),
            Self::Correlation(_) => false,
        }
    }

    #[inline]
    pub fn status(&self) -> &Status {
        match self {
            Self::Chainsaw(c) => &c.status,
            Self::Sigma(s) => &s.status,
            Self::Correlation(c) => &c.metadata.status,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Aggregate {
    #[serde(deserialize_with = "crate::ext::tau::deserialize_numeric")]
    pub count: Pattern,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Filter {
    Detection(Detection),
    #[serde(deserialize_with = "crate::ext::tau::deserialize_expression")]
    Expression(Expression),
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Chainsaw,
    Sigma,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chainsaw => write!(f, "chainsaw"),
            Self::Sigma => write!(f, "sigma"),
        }
    }
}

impl FromStr for Kind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "chainsaw" => Self::Chainsaw,
            "sigma" => Self::Sigma,
            _ => anyhow::bail!("unknown kind, must be: chainsaw, or sigma"),
        };
        Ok(v)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Critical,
    High,
    Medium,
    Low,
    #[serde(alias = "informational")]
    Info,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

impl FromStr for Level {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "info" => Self::Info,
            _ => anyhow::bail!("unknown level, must be: critical, high, medium, low or info"),
        };
        Ok(v)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Stable,
    Experimental,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Experimental => write!(f, "experimental"),
        }
    }
}

impl FromStr for Status {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "stable" => Self::Stable,
            "experimental" => Self::Experimental,
            _ => anyhow::bail!("unknown status, must be: stable or experimental"),
        };
        Ok(v)
    }
}
pub fn load(
    kind: Kind,
    path: &Path,
    kinds: &Option<HashSet<Kind>>,
    levels: &Option<HashSet<Level>>,
    statuses: &Option<HashSet<Status>>,
) -> crate::Result<Vec<Rule>> {
    load_rules(kind, path, kinds, levels, statuses, false)
}

/// Keep component definitions available while selecting the alerts shown by hunt.
pub fn load_for_hunt(
    kind: Kind,
    path: &Path,
    kinds: &Option<HashSet<Kind>>,
    levels: &Option<HashSet<Level>>,
    statuses: &Option<HashSet<Status>>,
) -> crate::Result<Vec<Rule>> {
    load_rules(kind, path, kinds, levels, statuses, true)
}

fn load_rules(
    kind: Kind,
    path: &Path,
    kinds: &Option<HashSet<Kind>>,
    levels: &Option<HashSet<Level>>,
    statuses: &Option<HashSet<Status>>,
    retain_dependencies: bool,
) -> crate::Result<Vec<Rule>> {
    if let Some(x) = path.extension()
        && x != "yml"
        && x != "yaml"
    {
        anyhow::bail!("rule must have a yaml file extension");
    }
    let mut rules = match kind {
        Kind::Chainsaw => {
            if let Some(kinds) = kinds.as_ref()
                && !kinds.contains(&Kind::Chainsaw)
            {
                return Ok(vec![]);
            }
            let rule = chainsaw::load(path)?;
            vec![Rule::Chainsaw(rule)]
        }
        Kind::Sigma => {
            if let Some(kinds) = kinds.as_ref()
                && !kinds.contains(&Kind::Sigma)
            {
                return Ok(vec![]);
            }
            sigma::load(path)?
                .into_iter()
                .map(|raw| -> crate::Result<Rule> {
                    if let Some(definition) = raw.get("correlation") {
                        let parse = || -> crate::Result<Rule> {
                            let mut meta: sigma::Metadata = serde_yaml::from_value(raw.clone())?;
                            meta.origin = path.to_owned();
                            let generate = meta.generate;
                            Ok(Rule::Correlation(correlation::Rule::parse(
                                meta,
                                definition.clone(),
                                generate,
                            )?))
                        };
                        return parse().map_err(|e| anyhow!(CorrelationError(e.to_string())));
                    }
                    let mut s: Sigma = serde_yaml::from_value(raw)?;
                    s.metadata.origin = path.to_owned();
                    s.tau.detection.expression = optimiser::coalesce(
                        s.tau.detection.expression,
                        &s.tau.detection.identifiers,
                    );
                    s.tau.detection.identifiers.clear();
                    s.tau.detection.expression = optimiser::shake(s.tau.detection.expression);
                    s.tau.detection.expression = optimiser::rewrite(s.tau.detection.expression);
                    // FIXME: Off until matrix optimisation is fixed upstream.
                    //s.tau.detection.expression = optimiser::matrix(s.tau.detection.expression);
                    Ok(Rule::Sigma(s))
                })
                .collect::<crate::Result<Vec<_>>>()?
        }
    };
    rules.retain_mut(|r| {
        let selected = levels.as_ref().is_none_or(|l| l.contains(r.level()))
            && statuses.as_ref().is_none_or(|s| s.contains(r.status()));
        if retain_dependencies {
            match r {
                Rule::Sigma(s) => {
                    s.metadata.filtered = !selected;
                    return true;
                }
                Rule::Correlation(c) => {
                    c.metadata.filtered = !selected;
                    return true;
                }
                _ => {}
            }
        }
        selected
    });
    Ok(rules)
}

pub fn lint(kind: &Kind, path: &Path) -> crate::Result<Vec<Filter>> {
    if let Some(x) = path.extension()
        && x != "yml"
        && x != "yaml"
    {
        anyhow::bail!("rule must have a yaml file extension");
    }
    let detections = match kind {
        Kind::Chainsaw => match chainsaw::load(path) {
            Ok(rule) => {
                vec![rule.filter]
            }
            Err(e) => {
                anyhow::bail!("{}", e);
            }
        },
        Kind::Sigma => load(Kind::Sigma, path, &None, &None, &None)?
            .into_iter()
            .filter_map(|r| match r {
                Rule::Sigma(s) => Some(Filter::Detection(s.tau.detection)),
                _ => None,
            })
            .collect(),
    };
    Ok(detections)
}
