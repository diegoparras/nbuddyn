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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ok: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub failed: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub canceled: i64,
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
}

impl History {
    /// Adds what one scan saw and forgets days older than `keep_days`.
    pub fn record(&mut self, delta: ExecutionDelta, score: u32, keep_days: u32) {
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
            if !tally.workflow_name.is_empty() {
                self.names.insert(tally.workflow_id, tally.workflow_name);
            }
        }

        let day = self.days.entry(delta.today.clone()).or_default();
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

        self.cursor = delta.upto;
        self.pending = delta.unfinished;
        self.today = delta.today;

        if let Some(cutoff) = day_number(&self.today).map(|n| day_name(n - i64::from(keep_days))) {
            self.days.retain(|day, _| *day >= cutoff);
            let days = &self.days;
            self.names
                .retain(|id, _| days.values().any(|d| d.runs.contains_key(id)));
        }
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
        let name = if instance == crate::settings::PRIMARY {
            FILE.to_owned()
        } else {
            format!("history-{instance}.json")
        };
        Self {
            dir: dir.into(),
            name,
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
    pub fn save(&self, history: &History) -> Result<(), String> {
        let text = serde_json::to_string(history).map_err(|e| e.to_string())?;
        write_atomically(&self.dir, &self.file(), text.as_bytes())
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
                canceled: 0
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
        // The latest name wins; a deleted workflow keeps showing by its id.
        assert_eq!(history.names["a"], "Ventas nuevas");
        assert!(!history.names.contains_key("b"));
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
