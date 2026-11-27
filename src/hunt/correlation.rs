use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use chrono::NaiveDateTime;
use tau_engine::{Document as TauDocument, Value as Tau};
use uuid::Uuid;

use super::{Detections, Document, Hit, Kind};
use crate::rule::{Rule, correlation};

/// Each entry is a group of matches on referenced base rules. Scope is the
/// entire hunt invocation, even when its inputs are split across files.
#[derive(Default)]
pub struct CorrelationState<'a> {
    groups: BTreeMap<(Uuid, Vec<Key>), Vec<Observation<'a>>>,
}

#[derive(Clone, Eq, Hash, PartialEq, Ord, PartialOrd)]
enum Key {
    String(String),
    Integer(i128),
    Float(u64),
    Bool(bool),
}

impl Key {
    fn read(mapped: &dyn TauDocument, field: &str) -> Option<Self> {
        match mapped.find(field)? {
            Tau::Bool(b) => Some(Self::Bool(b)),
            Tau::Int(i) => Some(Self::Integer(i.into())),
            Tau::UInt(u) => Some(Self::Integer(u.into())),
            Tau::Float(f) => Some(Self::Float(f.to_bits())),
            Tau::String(s) => Some(Self::String(s.into_owned())),
            _ => None,
        }
    }
}

struct Observation<'a> {
    component: usize,
    timestamp: NaiveDateTime,
    value: Option<Key>,
    hunt: Uuid,
    document: Arc<Document<'a>>,
}

pub(super) struct Bindings {
    pub(super) by_component: HashMap<Uuid, Vec<(Uuid, usize)>>,
    pub(super) hidden: HashSet<Uuid>,
}

impl Bindings {
    pub(super) fn resolve(rules: &BTreeMap<Uuid, Rule>) -> crate::Result<Self> {
        let mut by_component = HashMap::<_, Vec<_>>::new();
        let mut hidden = HashSet::new();
        let mut generated = HashSet::new();
        let mut directory_names = HashMap::<_, HashSet<Uuid>>::new();
        let mut local_names = HashMap::<_, HashSet<Uuid>>::new();
        let mut names = HashMap::<&str, HashSet<Uuid>>::new();
        for (rid, rule) in rules {
            if let Some(m) = rule.sigma_metadata() {
                if m.filtered {
                    hidden.insert(*rid);
                }
                for name in [m.id.as_deref(), m.component_name.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    directory_names
                        .entry((m.origin.parent(), name))
                        .or_default()
                        .insert(*rid);
                    local_names
                        .entry((m.origin.as_path(), name))
                        .or_default()
                        .insert(*rid);
                    names.entry(name).or_default().insert(*rid);
                }
            }
        }
        for (rid, rule) in rules {
            let Rule::Correlation(c) = rule else { continue };
            let mut components = HashSet::new();
            for (index, name) in c.rules.iter().enumerate() {
                let ids = local_names
                    .get(&(c.metadata.origin.as_path(), name.as_str()))
                    .or_else(|| directory_names.get(&(c.metadata.origin.parent(), name.as_str())))
                    .or_else(|| names.get(name.as_str()))
                    .ok_or_else(|| {
                        anyhow!(
                            "{}: unresolved correlation rule reference '{}'",
                            c.metadata.name,
                            name
                        )
                    })?;
                anyhow::ensure!(
                    ids.len() == 1,
                    "{}: ambiguous correlation rule reference '{}'",
                    c.metadata.name,
                    name
                );
                let component = *ids.iter().next().unwrap();
                let Rule::Sigma(base) = &rules[&component] else {
                    bail!(
                        "{}: chained correlation reference '{}' is unsupported",
                        c.metadata.name,
                        name
                    );
                };
                anyhow::ensure!(
                    base.aggregate.is_none(),
                    "{}: aggregate component '{}' is unsupported",
                    c.metadata.name,
                    name
                );
                anyhow::ensure!(
                    components.insert(component),
                    "{}: repeated component '{}'",
                    c.metadata.name,
                    name
                );
                if !c.metadata.filtered {
                    by_component
                        .entry(component)
                        .or_default()
                        .push((*rid, index));
                }
                hidden.insert(component);
                if !base.metadata.filtered && (c.generate || base.generate) {
                    generated.insert(component);
                }
            }
        }
        hidden.retain(|id| !generated.contains(id));
        Ok(Self {
            by_component,
            hidden,
        })
    }
}

impl<'a> CorrelationState<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe(
        &mut self,
        id: Uuid,
        rule: &correlation::Rule,
        component: usize,
        mapped: &dyn TauDocument,
        timestamp: NaiveDateTime,
        hunt: Uuid,
        document: &Arc<Document<'a>>,
    ) {
        let Some(group) = rule
            .group_by
            .iter()
            .map(|f| {
                let field = rule
                    .aliases
                    .get(f)
                    .map_or(f, |fields| &fields[&rule.rules[component]]);
                Key::read(mapped, field)
            })
            .collect::<Option<Vec<_>>>()
        else {
            return;
        };
        let value = match &rule.kind {
            correlation::Kind::ValueCount { field, .. } => {
                let Some(value) = Key::read(mapped, field) else {
                    return;
                };
                Some(value)
            }
            _ => None,
        };
        self.groups
            .entry((id, group))
            .or_default()
            .push(Observation {
                component,
                timestamp,
                value,
                hunt,
                document: Arc::clone(document),
            });
    }

    pub(super) fn extend(&mut self, other: Self) {
        for (key, mut rows) in other.groups {
            self.groups.entry(key).or_default().append(&mut rows);
        }
    }

    pub(super) fn finish(self, rules: &BTreeMap<Uuid, Rule>) -> crate::Result<Vec<Detections<'a>>> {
        let mut result = vec![];
        for ((rid, _), mut rows) in self.groups {
            let Rule::Correlation(rule) = &rules[&rid] else {
                unreachable!()
            };
            let mut timestamps = HashMap::new();
            for row in &rows {
                let key = (row.document.path, row.document.record_index);
                if let Some(previous) = timestamps.insert(key, row.timestamp) {
                    anyhow::ensure!(
                        previous == row.timestamp,
                        "conflicting mapped timestamps for {}#{} in correlation '{}'",
                        row.document.path.display(),
                        row.document.record_index.unwrap_or_default(),
                        rule.metadata.name
                    );
                }
            }
            rows.sort_by_key(|r| {
                (
                    r.timestamp,
                    r.document.path,
                    r.document.record_index,
                    r.component,
                )
            });
            // Mapping groups and multiple components can select the same source
            // record. Count it once; retain every component it actually matched.
            let mut events: Vec<Event> = vec![];
            for row in rows {
                if let Some(last) = events.last_mut()
                    && last.timestamp == row.timestamp
                    && last.document.path == row.document.path
                    && last.document.record_index == row.document.record_index
                {
                    anyhow::ensure!(
                        last.value == row.value,
                        "conflicting field mappings for a correlation record in {}",
                        last.document.path.display()
                    );
                    if last.components.last() != Some(&row.component) {
                        last.components.push(row.component);
                    }
                } else {
                    events.push(Event {
                        timestamp: row.timestamp,
                        hunt: row.hunt,
                        document: row.document,
                        value: row.value,
                        components: vec![row.component],
                    });
                }
            }
            let mut left = 0;
            let mut distinct = HashMap::<&Key, usize>::new();
            let mut positions = vec![Vec::new(); rule.rules.len()];
            let mut active_count_alert = false;
            for right in 0..events.len() {
                let current = &events[right];
                while current.timestamp - events[left].timestamp > rule.span {
                    if let Some(key) = &events[left].value {
                        let n = distinct.get_mut(key).unwrap();
                        *n -= 1;
                        if *n == 0 {
                            distinct.remove(key);
                        }
                    }
                    left += 1;
                }
                if let correlation::Kind::ValueCount { bounds, .. } = &rule.kind {
                    if distinct.is_empty()
                        || !bounds.iter().all(|(cmp, k)| cmp.test(distinct.len(), *k))
                    {
                        active_count_alert = false;
                    }
                } else {
                    for &component in &current.components {
                        positions[component].push(right);
                    }
                }
                if let Some(key) = &current.value {
                    *distinct.entry(key).or_default() += 1;
                }
                let window = &events[left..=right];
                let witnesses = match &rule.kind {
                    correlation::Kind::ValueCount { bounds, .. } => {
                        if !bounds.iter().all(|(cmp, k)| cmp.test(distinct.len(), *k)) {
                            continue;
                        }
                        // Counts are evaluated at event time, including all simultaneous records.
                        if events
                            .get(right + 1)
                            .is_some_and(|next| next.timestamp == current.timestamp)
                        {
                            continue;
                        }
                        if active_count_alert {
                            continue;
                        }
                        active_count_alert = true;
                        // One representative per distinct value proves the count.
                        // Prefer the most recent so the triggering record is included.
                        let mut seen = HashSet::new();
                        let mut indices: Vec<_> = (left..=right)
                            .rev()
                            .filter(|&i| seen.insert(events[i].value.as_ref().unwrap()))
                            .collect();
                        indices.reverse();
                        indices
                    }

                    correlation::Kind::Ordered => {
                        let Some(indices) = ordered(&events, &positions, left, right) else {
                            continue;
                        };
                        indices
                    }
                    correlation::Kind::Temporal { minimum } => {
                        if window.len() < *minimum {
                            continue;
                        }
                        let Some(indices) =
                            unordered(&positions, &current.components, left, right, *minimum)
                        else {
                            continue;
                        };
                        indices
                    }
                };
                result.push(Detections {
                    hits: smallvec::smallvec![Hit {
                        hunt: current.hunt,
                        rule: rid,
                        timestamp: current.timestamp
                    }],
                    kind: Kind::Aggregate {
                        documents: witnesses
                            .into_iter()
                            .map(|i| {
                                let mut document = events[i].document.as_ref().clone();
                                document.source_hunt = Some(events[i].hunt);
                                document
                            })
                            .collect(),
                    },
                });
            }
        }
        Ok(result)
    }
}

struct Event<'a> {
    timestamp: NaiveDateTime,
    hunt: Uuid,
    document: Arc<Document<'a>>,
    value: Option<Key>,
    components: Vec<usize>,
}

// Work backwards from the triggering event, taking the latest eligible event
// for each preceding step. Equal timestamps cannot prove order.
fn ordered(
    events: &[Event],
    positions: &[Vec<usize>],
    left: usize,
    right: usize,
) -> Option<Vec<usize>> {
    if positions.last()?.last() != Some(&right) {
        return None;
    }
    let mut until = right;
    let mut indices = vec![right];
    for step in positions[..positions.len() - 1].iter().rev() {
        let end = step.partition_point(|&i| events[i].timestamp < events[until].timestamp);
        until = *step.get(end.checked_sub(1)?)?;
        if until < left {
            return None;
        }
        indices.push(until);
    }
    indices.reverse();
    Some(indices)
}

// Assign a distinct source record to each rule. Only the last minimum
// candidates per rule are needed: at most minimum - 1 records can be taken
// by other roles. This bounds the work even for a very dense time window.
fn unordered(
    positions: &[Vec<usize>],
    last_components: &[usize],
    left: usize,
    right: usize,
    minimum: usize,
) -> Option<Vec<usize>> {
    fn assign(
        step: usize,
        choices: &[&[usize]],
        assigned: &mut HashMap<usize, usize>,
        visited: &mut HashSet<usize>,
    ) -> bool {
        for &i in choices[step].iter().rev() {
            if !visited.insert(i) {
                continue;
            }
            if assigned
                .get(&i)
                .copied()
                .is_none_or(|prev| assign(prev, choices, assigned, visited))
            {
                assigned.insert(i, step);
                return true;
            }
        }
        false
    }
    let choices: Vec<_> = positions
        .iter()
        .map(|indices| {
            let lower = indices.len().saturating_sub(minimum);
            let recent = &indices[lower..];
            &recent[recent.partition_point(|&i| i < left)..]
        })
        .collect();
    if choices.iter().filter(|c| !c.is_empty()).count() < minimum {
        return None;
    }
    for &last_step in last_components {
        let mut matched = HashMap::new();
        for step in (0..choices.len()).filter(|&step| step != last_step) {
            if matched.len() + 1 == minimum {
                break;
            }
            let mut visited = HashSet::from([right]);
            assign(step, &choices, &mut matched, &mut visited);
        }
        if matched.len() + 1 == minimum {
            let mut indices: Vec<_> = matched.into_keys().chain([right]).collect();
            indices.sort_unstable();
            return Some(indices);
        }
    }
    None
}
