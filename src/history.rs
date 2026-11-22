//! nbuddyn's own memory: how many executions each workflow had per day and how
//! they ended, plus the score of each day.
//!
//! n8n prunes its executions and can be told not to save the successful ones,
//! so its own history is short and partial. nbuddyn counts each execution once
//! as it goes by and keeps only the totals, in one small JSON file. No
//! execution data is ever read or stored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::db::ExecutionDelta;
use crate::model::Workflow;
use crate::radar::Finding;

const FILE: &str = "history.json";

/// How an execution ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Failed,
    Canceled,
}

impl Outcome {
    /// `None` for an execution that has not finished.
    pub fn of_status(status: &str) -> Option<Self> {
        match status {
            "success" => Some(Self::Ok),
            "error" | "crashed" => Some(Self::Failed),
            "canceled" => Some(Self::Canceled),
            _ => None,
        }
    }
}

/// Finished executions of one workflow on one day with one outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tally {
    pub workflow_id: String,
    /// Empty when the workflow no longer exists.
    pub workflow_name: String,
    pub day: String,
    pub outcome: Outcome,
    pub count: i64,
    /// How many of them have a known duration, their total and the longest,
    /// in milliseconds. All zero when nbuddyn may not read when they stopped.
    pub timed: i64,
    pub ms: i64,
    pub slowest: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ok: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub failed: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub canceled: i64,
    /// Executions with a known duration, their total and the longest, in
    /// milliseconds.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub timed: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ms: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub slowest: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl Counts {
    pub fn total(&self) -> i64 {
        self.ok + self.failed + self.canceled
    }

    fn add(&mut self, other: Counts) {
        self.ok += other.ok;
        self.failed += other.failed;
        self.canceled += other.canceled;
        self.timed += other.timed;
        self.ms += other.ms;
        self.slowest = self.slowest.max(other.slowest);
    }
}

/// The lowest, highest and latest score seen in one day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreDay {
    pub min: u32,
    pub max: u32,
    pub last: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Day {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<ScoreDay>,
    /// Executions by workflow id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub runs: BTreeMap<String, Counts>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct History {
    /// The highest execution id already counted.
    #[serde(default)]
    pub cursor: i64,
    /// Executions seen unfinished, to look at again.
    #[serde(default)]
    pub pending: Vec<i64>,
    /// The date of the latest scan, `YYYY-MM-DD`.
    #[serde(default)]
    pub today: String,
    /// Last known name of each workflow id, kept after the workflow is deleted.
    #[serde(default)]
    pub names: BTreeMap<String, String>,
    /// By date, `YYYY-MM-DD`.
    #[serde(default)]
    pub days: BTreeMap<String, Day>,
    /// What the previous scan saw, to tell what changed since. `None` before
    /// the first scan that looked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<Seen>,
    /// What changed, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
}

/// The findings and workflows of the previous scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// By finding key.
    #[serde(default)]
    pub findings: BTreeMap<String, SeenFinding>,
    /// By workflow id.
    #[serde(default)]
    pub workflows: BTreeMap<String, SeenWorkflow>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenFinding {
    /// When it first appeared, in seconds since 1970. 0 for the findings that
    /// were already there the first time nbuddyn looked.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub since: u64,
    pub check: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenWorkflow {
    pub name: String,
    pub active: bool,
    pub print: u64,
}

/// Something that changed between two scans.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Seconds since 1970, of the scan that noticed.
    pub at: u64,
    /// `finding_new`, `finding_resolved`, or `workflow_` followed by
    /// `created`, `deleted`, `changed`, `renamed`, `activated`, `deactivated`.
    pub kind: String,
    /// For findings: which check, and how severe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Who saved the workflow, when n8n says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// The most events kept; older ones go first.
const EVENTS_MAX: usize = 5000;
/// A workflow counts as having run "most days" with this many days of runs...
const USUAL_DAYS: usize = 7;
/// ...out of this many days...
const USUAL_WINDOW: i64 = 14;
/// ...and as gone quiet after this many days without a single run.
const QUIET_DAYS: i64 = 3;

impl History {
    /// Compares this scan with the previous one, writes down what changed,
    /// remembers this scan for the next comparison, and returns what changed. The first time there is
    /// nothing to compare with, so nothing is written down.
    pub fn observe(
        &mut self,
        now: u64,
        findings: &[Finding],
        workflows: &[Workflow],
        authors: &std::collections::HashMap<String, String>,
        keep_days: u32,
    ) -> Vec<Event> {
        let previous = self.seen.take();
        let mut seen = Seen::default();
        let mut events = Vec::new();

        for f in findings {
            let key = f.key();
            let known = previous.as_ref().and_then(|p| p.findings.get(&key));
            let entry = SeenFinding {
                since: match (&previous, known) {
                    (_, Some(known)) => known.since,
                    (Some(_), None) => now,
                    (None, None) => 0,
                },
                check: f.check.to_owned(),
                severity: severity_name(f),
                workflow: f.workflow.clone(),
                node: f.node.clone(),
                path: f.path(),
            };
            if previous.is_some() && known.is_none() {
                events.push(Event {
                    at: now,
                    kind: "finding_new".into(),
                    check: Some(entry.check.clone()),
                    severity: Some(entry.severity.clone()),
                    workflow: entry.workflow.clone(),
                    node: entry.node.clone(),
                    detail: f.detail.clone(),
                    path: entry.path.clone(),
                    author: None,
                });
            }
            seen.findings.insert(key, entry);
        }
        for (key, gone) in previous.iter().flat_map(|p| &p.findings) {
            if !seen.findings.contains_key(key) {
                events.push(Event {
                    at: now,
                    kind: "finding_resolved".into(),
                    check: Some(gone.check.clone()),
                    severity: Some(gone.severity.clone()),
                    workflow: gone.workflow.clone(),
                    node: gone.node.clone(),
                    detail: None,
                    path: gone.path.clone(),
                    author: None,
                });
            }
        }

        let about = |kind: &str, id: &str, name: &str, detail: Option<String>| Event {
            at: now,
            kind: format!("workflow_{kind}"),
            workflow: Some(name.to_owned()),
            detail,
            path: crate::radar::workflow_path(id),
            author: authors.get(id).cloned().filter(|a| !a.trim().is_empty()),
            ..Event::default()
        };
        for wf in workflows.iter().filter(|w| !w.archived) {
            let entry = SeenWorkflow {
                name: wf.name.clone(),
                active: wf.active,
                print: wf.print,
            };
            if let Some(previous) = &previous {
                match previous.workflows.get(&wf.id) {
                    None => events.push(about("created", &wf.id, &wf.name, None)),
                    Some(before) => {
                        if before.name != entry.name {
                            let was = Some(before.name.clone());
                            events.push(about("renamed", &wf.id, &wf.name, was));
                        }
                        if before.print != entry.print {
                            events.push(about("changed", &wf.id, &wf.name, None));
                        }
                        if before.active != entry.active {
                            let kind = if entry.active {
                                "activated"
                            } else {
                                "deactivated"
                            };
                            events.push(about(kind, &wf.id, &wf.name, None));
                        }
                    }
                }
            }
            seen.workflows.insert(wf.id.clone(), entry);
        }
        for (id, gone) in previous.iter().flat_map(|p| &p.workflows) {
            if !seen.workflows.contains_key(id) {
                let mut event = about("deleted", id, &gone.name, None);
                // It is gone: there is nowhere to link to and nobody to name.
                event.path = None;
                event.author = None;
                events.push(event);
            }
        }

        self.seen = Some(seen);
        self.events.extend(events.iter().cloned());
        let oldest = now.saturating_sub(u64::from(keep_days) * 86_400);
        self.events.retain(|e| e.at >= oldest);
        if self.events.len() > EVENTS_MAX {
            let extra = self.events.len() - EVENTS_MAX;
            self.events.drain(..extra);
        }
        events
    }

    /// Workflows that ran on most of the days before the last few and not once
    /// since: their id and the last day they ran.
    pub fn quiet(&self) -> Vec<(String, String)> {
        let Some(today) = day_number(&self.today) else {
            return Vec::new();
        };
        let ran_on = |number: i64, id: &str| {
            self.days
                .get(&day_name(number))
                .and_then(|d| d.runs.get(id))
                .is_some_and(|c| c.total() > 0)
        };
        let recent = (today - QUIET_DAYS + 1)..=today;
        let before = (today - QUIET_DAYS - USUAL_WINDOW + 1)..=(today - QUIET_DAYS);
        self.names
            .keys()
            .filter(|id| !recent.clone().any(|n| ran_on(n, id)))
            .filter_map(|id| {
                let days: Vec<i64> = before.clone().filter(|n| ran_on(*n, id)).collect();
                let last = *days.last()?;
                (days.len() >= USUAL_DAYS).then(|| (id.clone(), day_name(last)))
            })
            .collect()
    }

    /// When a finding first appeared, if it appeared after nbuddyn started
    /// looking.
    pub fn since(&self, key: &str) -> Option<u64> {
        self.seen
            .as_ref()
            .and_then(|s| s.findings.get(key))
            .map(|f| f.since)
            .filter(|since| *since > 0)
    }

    /// The events at or after `from`, newest first.
    pub fn events_since(&self, from: u64) -> Vec<&Event> {
        self.events
            .iter()
            .rev()
            .take_while(|e| e.at >= from)
            .collect()
    }
}

fn severity_name(f: &Finding) -> String {
    serde_json::to_value(f.severity)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl History {
    /// Adds the executions one scan saw finish and moves the cursor past them.
    pub fn record_runs(&mut self, delta: ExecutionDelta) {
        for tally in delta.finished {
            let counts = self
                .days
                .entry(tally.day)
                .or_default()
                .runs
                .entry(tally.workflow_id.clone())
                .or_default();
            match tally.outcome {
                Outcome::Ok => counts.ok += tally.count,
                Outcome::Failed => counts.failed += tally.count,
                Outcome::Canceled => counts.canceled += tally.count,
            }
            counts.timed += tally.timed;
            counts.ms += tally.ms;
            counts.slowest = counts.slowest.max(tally.slowest);
            if !tally.workflow_name.is_empty() {
                self.names.insert(tally.workflow_id, tally.workflow_name);
            } else {
                // Still listed, under its id, when the workflow is gone.
                self.names
                    .entry(tally.workflow_id.clone())
                    .or_insert(tally.workflow_id);
            }
        }
        self.cursor = delta.upto;
        self.pending = delta.unfinished;
        self.today = delta.today;
    }

    /// Notes today's score and forgets days older than `keep_days`.
    pub fn record_score(&mut self, today: &str, score: u32, keep_days: u32) {
        let day = self.days.entry(today.to_owned()).or_default();
        day.score = Some(match day.score {
            None => ScoreDay {
                min: score,
                max: score,
                last: score,
            },
            Some(seen) => ScoreDay {
                min: seen.min.min(score),
                max: seen.max.max(score),
                last: score,
            },
        });
        if let Some(cutoff) = day_number(today).map(|n| day_name(n - i64::from(keep_days))) {
            self.days.retain(|day, _| *day >= cutoff);
            let days = &self.days;
            self.names
                .retain(|id, _| days.values().any(|d| d.runs.contains_key(id)));
        }
    }

    /// Both steps of one scan, in order.
    #[cfg(test)]
    pub fn record(&mut self, delta: ExecutionDelta, score: u32, keep_days: u32) {
        let today = delta.today.clone();
        self.record_runs(delta);
        self.record_score(&today, score, keep_days);
    }

    /// One row per day and workflow that ran, for the last `span` days,
    /// oldest first.
    pub fn rows(&self, span: u32) -> Vec<Row> {
        let Some(today) = day_number(&self.today) else {
            return Vec::new();
        };
        let first = day_name(today - i64::from(span.max(1)) + 1);
        self.days
            .range(first..)
            .flat_map(|(day, stored)| {
                stored.runs.iter().map(move |(id, counts)| Row {
                    day: day.clone(),
                    workflow: self.names.get(id).cloned().unwrap_or_else(|| id.clone()),
                    counts: *counts,
                })
            })
            .collect()
    }

    /// The last `span` days ending today, oldest first, with empty days filled in.
    pub fn view(&self, span: u32) -> View {
        let Some(today) = day_number(&self.today) else {
            return View::default();
        };
        let first = today - i64::from(span.max(1)) + 1;

        let mut workflows: BTreeMap<&str, WorkflowView> = BTreeMap::new();
        let mut days = Vec::new();
        let mut totals = Counts::default();
        for number in first..=today {
            let name = day_name(number);
            let stored = self.days.get(&name);
            let mut counts = Counts::default();
            for (id, runs) in stored.iter().flat_map(|d| &d.runs) {
                counts.add(*runs);
                let entry = workflows.entry(id).or_insert_with(|| WorkflowView {
                    name: self.names.get(id).cloned().unwrap_or_else(|| id.clone()),
                    path: crate::radar::workflow_path(id),
                    counts: Counts::default(),
                    last_day: String::new(),
                });
                entry.counts.add(*runs);
                entry.last_day.clone_from(&name);
            }
            totals.add(counts);
            days.push(DayView {
                day: name,
                counts,
                score: stored.and_then(|d| d.score).map(|s| s.last),
            });
        }

        let mut workflows: Vec<WorkflowView> = workflows.into_values().collect();
        workflows.sort_by(|a, b| {
            b.counts
                .total()
                .cmp(&a.counts.total())
                .then_with(|| a.name.cmp(&b.name))
        });
        View {
            since: self.days.keys().next().cloned(),
            totals,
            days,
            workflows,
        }
    }
}

/// The executions of one workflow on one day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub day: String,
    pub workflow: String,
    pub counts: Counts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct View {
    /// The oldest day nbuddyn remembers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    pub totals: Counts,
    pub days: Vec<DayView>,
    /// Workflows that ran in the span, busiest first.
    pub workflows: Vec<WorkflowView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DayView {
    pub day: String,
    #[serde(flatten)]
    pub counts: Counts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkflowView {
    pub name: String,
    /// Path under n8n's address; the workflow may no longer exist there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(flatten)]
    pub counts: Counts,
    pub last_day: String,
}

/// Where the history lives on disk.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    name: String,
}

impl Store {
    /// The history of one instance. The first instance keeps the plain file
    /// name it had before nbuddyn could watch more than one n8n.
    pub fn new(dir: impl Into<PathBuf>, instance: &str) -> Self {
        Self {
            dir: dir.into(),
            name: Self::file_name(instance),
        }
    }

    pub fn file_name(instance: &str) -> String {
        if instance == crate::settings::PRIMARY {
            FILE.to_owned()
        } else {
            format!("history-{instance}.json")
        }
    }

    fn file(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    /// Reads the saved history, or starts an empty one when there is none. A
    /// file that cannot be understood is set aside, never overwritten.
    pub fn load(&self) -> Result<History, String> {
        let file = self.file();
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(History::default()),
            Err(e) => return Err(format!("cannot read {}: {e}", file.display())),
        };
        match serde_json::from_str(&text) {
            Ok(history) => Ok(history),
            Err(e) => {
                let aside = self.dir.join(format!("{}.unreadable", self.name));
                std::fs::rename(&file, &aside).map_err(|rename| {
                    format!(
                        "{} is not valid ({e}) and could not be set aside: {rename}",
                        file.display()
                    )
                })?;
                eprintln!(
                    "history: {} was not valid ({e}); kept as {} and starting again",
                    file.display(),
                    aside.display()
                );
                Ok(History::default())
            }
        }
    }

    /// Replaces the file in one step, so a crash never leaves half a history.
    #[cfg(test)]
    pub fn save(&self, history: &History) -> Result<(), String> {
        self.write(&Self::encode(history)?)
    }

    /// The history as it goes to disk. Separate from writing it, so the
    /// history is only held for as long as this takes.
    pub fn encode(history: &History) -> Result<String, String> {
        serde_json::to_string(history).map_err(|e| e.to_string())
    }

    pub fn write(&self, encoded: &str) -> Result<(), String> {
        write_atomically(&self.dir, &self.file(), encoded.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", self.file().display()))
    }
}

/// Replaces `file` inside `dir` in one step, so a crash never leaves half a file.
pub fn write_atomically(dir: &Path, file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let mut partial = file.as_os_str().to_owned();
    partial.push(".partial");
    let mut out = std::fs::File::create(&partial)?;
    out.write_all(bytes)?;
    out.sync_all()?;
    std::fs::rename(&partial, file)
}

/// Days since 1970-01-01 for a `YYYY-MM-DD` date.
fn day_number(day: &str) -> Option<i64> {
    let mut parts = day.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let date: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&date) {
        return None;
    }
    // Counts from March so the leap day falls at the end of the year.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + date - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// The `YYYY-MM-DD` date for a number of days since 1970-01-01.
fn day_name(number: i64) -> String {
    let shifted = number + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let date = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = (shifted_month + 2) % 12 + 1;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{date:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(id: &str, name: &str, day: &str, outcome: Outcome, count: i64) -> Tally {
        Tally {
            workflow_id: id.into(),
            workflow_name: name.into(),
            day: day.into(),
            outcome,
            count,
            timed: 0,
            ms: 0,
            slowest: 0,
        }
    }

    fn delta(today: &str, upto: i64, finished: Vec<Tally>) -> ExecutionDelta {
        ExecutionDelta {
            today: today.into(),
            upto,
            finished,
            unfinished: Vec::new(),
        }
    }

    #[test]
    fn dates_convert_both_ways() {
        assert_eq!(day_number("1970-01-01"), Some(0));
        assert_eq!(day_number("2026-11-22"), Some(20_779));
        for day in ["2024-02-29", "2025-12-31", "2026-01-01", "2000-03-01"] {
            assert_eq!(day_name(day_number(day).unwrap()), day);
        }
        assert_eq!(
            day_name(day_number("2026-03-01").unwrap() - 1),
            "2026-02-28"
        );
        assert_eq!(day_number("2026-13-01"), None);
        assert_eq!(day_number("yesterday"), None);
    }

    #[test]
    fn executions_add_up_by_day_and_workflow() {
        let mut history = History::default();
        history.record(
            delta(
                "2026-11-21",
                40,
                vec![
                    tally("a", "Ventas", "2026-11-20", Outcome::Ok, 10),
                    tally("a", "Ventas", "2026-11-21", Outcome::Failed, 2),
                ],
            ),
            70,
            400,
        );
        let mut next = delta(
            "2026-11-22",
            55,
            vec![
                tally("a", "Ventas nuevas", "2026-11-21", Outcome::Ok, 3),
                tally("b", "", "2026-11-22", Outcome::Canceled, 1),
            ],
        );
        next.unfinished = vec![51, 54];
        history.record(next, 64, 400);
        history.record(delta("2026-11-22", 55, vec![]), 80, 400);

        assert_eq!((history.cursor, history.pending.len()), (55, 0));
        let day = &history.days["2026-11-21"];
        assert_eq!(
            day.runs["a"],
            Counts {
                ok: 3,
                failed: 2,
                ..Counts::default()
            }
        );
        assert_eq!(day.score.map(|s| s.last), Some(70));
        assert_eq!(
            history.days["2026-11-22"].score,
            Some(ScoreDay {
                min: 64,
                max: 80,
                last: 80
            })
        );
        // The latest name wins; a workflow that is gone shows under its id.
        assert_eq!(history.names["a"], "Ventas nuevas");
        assert_eq!(history.names["b"], "b");
    }

    #[test]
    fn view_fills_empty_days_and_ranks_workflows() {
        let mut history = History::default();
        history.record(
            delta(
                "2026-11-22",
                9,
                vec![
                    tally("a", "Ventas", "2026-11-20", Outcome::Ok, 4),
                    tally("b", "Stock", "2026-11-22", Outcome::Failed, 6),
                    tally("b", "Stock", "2026-11-22", Outcome::Ok, 1),
                    tally("c", "Viejo", "2026-11-01", Outcome::Ok, 99),
                ],
            ),
            53,
            400,
        );
        let view = history.view(3);

        let days: Vec<(&str, i64)> = view
            .days
            .iter()
            .map(|d| (d.day.as_str(), d.counts.total()))
            .collect();
        assert_eq!(
            days,
            vec![("2026-11-20", 4), ("2026-11-21", 0), ("2026-11-22", 7)]
        );
        assert_eq!(view.days[2].score, Some(53));
        assert_eq!(view.totals.total(), 11);
        let names: Vec<&str> = view.workflows.iter().map(|w| w.name.as_str()).collect();
        assert_eq!(names, vec!["Stock", "Ventas"]);
        assert_eq!(view.workflows[0].last_day, "2026-11-22");
        assert_eq!(view.since.as_deref(), Some("2026-11-01"));
    }

    #[test]
    fn old_days_are_forgotten_with_their_names() {
        let mut history = History::default();
        history.record(
            delta(
                "2026-11-22",
                9,
                vec![
                    tally("old", "Viejo", "2026-11-10", Outcome::Ok, 1),
                    tally("new", "Nuevo", "2026-11-20", Outcome::Ok, 1),
                ],
            ),
            90,
            7,
        );
        assert_eq!(
            history.days.keys().collect::<Vec<_>>(),
            vec!["2026-11-20", "2026-11-22"]
        );
        assert_eq!(history.names.keys().collect::<Vec<_>>(), vec!["new"]);
    }

    fn finding(check: &'static str, workflow: &str) -> Finding {
        Finding {
            check,
            severity: crate::radar::Severity::Medium,
            workflow: Some(workflow.into()),
            node: None,
            detail: None,
            active: Some(true),
            workflow_id: Some(workflow.into()),
            subject: None,
        }
    }

    fn workflow(id: &str, name: &str, active: bool, nodes: &str) -> Workflow {
        Workflow::from_raw(id.into(), name.into(), active, false, nodes, None)
    }

    #[test]
    fn the_first_look_is_a_baseline_and_later_looks_report_what_changed() {
        let authors = std::collections::HashMap::from([("w1".to_owned(), "Ana Paz".to_owned())]);
        let mut history = History::default();
        let _ = history.observe(
            100,
            &[finding("no_error_workflow", "w1")],
            &[
                workflow("w1", "Ventas", true, "[]"),
                workflow("w2", "Stock", true, "[]"),
            ],
            &authors,
            400,
        );
        assert!(history.events.is_empty());
        assert_eq!(
            history.since(&finding("no_error_workflow", "w1").key()),
            None
        );

        let _ = history.observe(
            200,
            &[finding("public_entry_no_auth", "w1")],
            &[
                workflow("w1", "Ventas 2", false, r#"[{"name":"a"}]"#),
                workflow("w3", "Nuevo", true, "[]"),
            ],
            &authors,
            400,
        );
        let kinds: Vec<(&str, Option<&str>)> = history
            .events
            .iter()
            .map(|e| (e.kind.as_str(), e.workflow.as_deref()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("finding_new", Some("w1")),
                ("finding_resolved", Some("w1")),
                ("workflow_renamed", Some("Ventas 2")),
                ("workflow_changed", Some("Ventas 2")),
                ("workflow_deactivated", Some("Ventas 2")),
                ("workflow_created", Some("Nuevo")),
                ("workflow_deleted", Some("Stock")),
            ]
        );
        let renamed = &history.events[2];
        assert_eq!(renamed.detail.as_deref(), Some("Ventas"));
        assert_eq!(renamed.author.as_deref(), Some("Ana Paz"));
        assert_eq!(renamed.path.as_deref(), Some("/workflow/w1"));
        assert_eq!(history.events[6].path, None);
        assert_eq!(
            history.since(&finding("public_entry_no_auth", "w1").key()),
            Some(200)
        );

        // Nothing changed: nothing is added, and old events age out.
        let same = [
            workflow("w1", "Ventas 2", false, r#"[{"name":"a"}]"#),
            workflow("w3", "Nuevo", true, "[]"),
        ];
        let _ = history.observe(
            300,
            &[finding("public_entry_no_auth", "w1")],
            &same,
            &authors,
            400,
        );
        assert_eq!(history.events.len(), 7);
        assert_eq!(history.events_since(250).len(), 0);
        assert_eq!(history.events_since(200).len(), 7);
        let _ = history.observe(
            200 + 2 * 86_400,
            &[finding("public_entry_no_auth", "w1")],
            &same,
            &authors,
            1,
        );
        assert!(history.events.is_empty());
    }

    #[test]
    fn a_workflow_that_ran_most_days_and_stopped_is_noticed() {
        let mut history = History::default();
        let mut tallies = Vec::new();
        // "daily" ran every day until four days ago; "rare" ran twice; "alive" still runs.
        for back in 4..18 {
            tallies.push(tally(
                "daily",
                "Diario",
                &day_name(20_779 - back),
                Outcome::Ok,
                3,
            ));
        }
        for back in [5, 12] {
            tallies.push(tally(
                "rare",
                "Raro",
                &day_name(20_779 - back),
                Outcome::Ok,
                1,
            ));
        }
        for back in 0..18 {
            tallies.push(tally(
                "alive",
                "Vivo",
                &day_name(20_779 - back),
                Outcome::Failed,
                1,
            ));
        }
        history.record(delta("2026-11-22", 9, tallies), 80, 400);
        assert_eq!(
            history.quiet(),
            vec![("daily".to_owned(), "2026-11-18".to_owned())]
        );
    }

    #[test]
    fn history_survives_a_restart_and_a_broken_file_is_kept_aside() {
        let dir = std::env::temp_dir().join(format!("nbuddyn-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(&dir, crate::settings::PRIMARY);
        assert_eq!(store.load().unwrap(), History::default());

        let mut history = History::default();
        history.record(
            delta(
                "2026-11-22",
                7,
                vec![tally("a", "Ventas", "2026-11-22", Outcome::Ok, 5)],
            ),
            88,
            400,
        );
        store.save(&history).unwrap();
        assert_eq!(store.load().unwrap(), history);

        std::fs::write(dir.join(FILE), "{ not json").unwrap();
        assert_eq!(store.load().unwrap(), History::default());
        assert!(dir.join("history.json.unreadable").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
