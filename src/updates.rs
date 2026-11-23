//! Tells whether the n8n being watched is behind what n8n has published.
//!
//! This is the one thing nbuddyn asks the outside world, so it is off until
//! someone turns it on. When it is on, nbuddyn asks two public lists once a
//! day and sends nothing about the instance: the address it asks for is the
//! same whoever asks.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::radar::Severity;

/// A released version: major, minor, patch.
pub type Version = (u64, u64, u64);

/// Where n8n says which version is the stable one.
const STABLE_URL: &str = "https://registry.npmjs.org/-/package/n8n/dist-tags";
/// Where every published n8n image is listed, newest first.
const TAGS_URL: &str = "https://hub.docker.com/v2/repositories/n8nio/n8n/tags";
/// How long an answer is good for.
const FRESH_SECONDS: u64 = 24 * 3600;
/// After a failure, how long before asking again.
const RETRY_SECONDS: u64 = 3600;
/// How far back the list of images is read.
const PAGES: u32 = 3;

/// What n8n has published, as far as it matters to one installed version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Latest {
    /// The version n8n calls stable.
    pub stable: Option<Version>,
    /// The newest release with the same major number as the one installed.
    pub in_line: Option<Version>,
}

/// Reads `3.3.0`, and nothing looser: no `v`, no `-beta`, no `3.3`.
pub fn parse(text: &str) -> Option<Version> {
    let mut parts = text.trim().split('.');
    let mut next = || {
        parts
            .next()
            .filter(|p| !p.is_empty() && p.len() <= 6 && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse().ok())
    };
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

pub fn show(version: Version) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

/// Whether the installed version is behind, how much it matters, and the
/// version to move to. Being ahead of the stable one is not being behind.
pub fn verdict(installed: Version, latest: Latest) -> Option<(Severity, Version)> {
    if let Some(stable) = latest.stable.filter(|stable| stable.0 > installed.0) {
        // A whole line behind: this one stops getting fixes first.
        return Some((Severity::Medium, stable));
    }
    let same_line = [latest.in_line, latest.stable]
        .into_iter()
        .flatten()
        .filter(|v| v.0 == installed.0 && *v > installed)
        .max()?;
    Some((Severity::Low, same_line))
}

#[derive(Default)]
pub struct Updates {
    /// By major number: when it was asked, and what came back.
    known: Mutex<HashMap<u64, (u64, Option<Latest>)>>,
}

impl Updates {
    /// What is published for the line `installed` is on, asking at most once
    /// a day. `None` when the lists could not be read.
    pub async fn latest(&self, installed: Version, now: u64) -> Option<Latest> {
        let remembered = self
            .known
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&installed.0)
            .copied();
        if let Some((asked, answer)) = remembered {
            let good_for = if answer.is_some() {
                FRESH_SECONDS
            } else {
                RETRY_SECONDS
            };
            if now.saturating_sub(asked) < good_for {
                return answer;
            }
        }
        let answer = ask(installed.0).await;
        if let Err(reason) = &answer {
            eprintln!("update check failed: {reason}");
        }
        let answer = answer.ok();
        self.known
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(installed.0, (now, answer));
        answer
    }
}

async fn ask(major: u64) -> Result<Latest, String> {
    let stable = match crate::http::get(STABLE_URL).await {
        Ok(answer) if answer.status == 200 => stable_of(&answer.body),
        Ok(answer) => return Err(format!("{STABLE_URL} answered {}", answer.status)),
        Err(reason) => return Err(reason),
    };
    let mut in_line = None;
    for page in 1..=PAGES {
        let url =
            format!("{TAGS_URL}?page_size=100&ordering=last_updated&name={major}.&page={page}");
        let answer = crate::http::get(&url).await?;
        if answer.status != 200 {
            // Past the last page the list answers 404; that is not a failure.
            if page > 1 {
                break;
            }
            return Err(format!("{TAGS_URL} answered {}", answer.status));
        }
        let (newest, more) = newest_of(&answer.body, major);
        in_line = in_line.max(newest);
        if !more {
            break;
        }
    }
    Ok(Latest { stable, in_line })
}

/// The stable version in npm's list of labels.
fn stable_of(body: &str) -> Option<Version> {
    let labels: Value = serde_json::from_str(body).ok()?;
    ["stable", "latest"]
        .iter()
        .find_map(|label| labels.get(label).and_then(Value::as_str).and_then(parse))
}

/// The newest plain release of one line in a page of image tags, and whether
/// there is another page.
fn newest_of(body: &str, major: u64) -> (Option<Version>, bool) {
    let Ok(page) = serde_json::from_str::<Value>(body) else {
        return (None, false);
    };
    let newest = page
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tag| tag.get("name").and_then(Value::as_str).and_then(parse))
        .filter(|version| version.0 == major)
        .max();
    let more = page.get("next").is_some_and(|next| next.is_string());
    (newest, more)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_releases_count_as_versions() {
        assert_eq!(parse("3.3.0"), Some((3, 3, 0)));
        assert_eq!(parse(" 2.48.8 "), Some((2, 48, 8)));
        for not in [
            "3.3",
            "v3.3.0",
            "3.3.0-beta",
            "3.3.0-arm64",
            "3.3.0.1",
            "latest",
            "",
            "3..0",
        ] {
            assert_eq!(parse(not), None, "{not}");
        }
        assert_eq!(show((3, 10, 2)), "3.10.2");
        // Compared as numbers, not as text.
        assert!(parse("3.10.0") > parse("3.9.9"));
    }

    #[test]
    fn behind_ahead_and_level_are_told_apart() {
        let latest = |stable, in_line| Latest {
            stable: Some(stable),
            in_line,
        };
        // A newer fix or minor on the same line: worth knowing, not urgent.
        assert_eq!(
            verdict((3, 3, 0), latest((2, 48, 8), Some((3, 4, 1)))),
            Some((Severity::Low, (3, 4, 1)))
        );
        // Ahead of the stable line and nothing newer on its own: nothing to say.
        assert_eq!(
            verdict((3, 3, 0), latest((2, 48, 8), Some((3, 3, 0)))),
            None
        );
        assert_eq!(verdict((3, 3, 0), latest((2, 48, 8), None)), None);
        // A whole line behind the stable one matters more.
        assert_eq!(
            verdict((1, 123, 0), latest((2, 48, 8), Some((1, 123, 5)))),
            Some((Severity::Medium, (2, 48, 8)))
        );
        // The stable label alone is enough when it is on the same line.
        assert_eq!(
            verdict((2, 40, 0), latest((2, 48, 8), None)),
            Some((Severity::Low, (2, 48, 8)))
        );
        assert_eq!(
            verdict((2, 48, 8), latest((2, 48, 8), Some((2, 48, 8)))),
            None
        );
    }

    #[test]
    fn the_public_lists_are_read_as_they_come() {
        let labels = r#"{"stable":"2.48.8","next":"2.49.4","beta":"2.49.4","latest":"2.48.8"}"#;
        assert_eq!(stable_of(labels), Some((2, 48, 8)));
        assert_eq!(stable_of(r#"{"latest":"2.47.0"}"#), Some((2, 47, 0)));
        assert_eq!(stable_of("not json"), None);

        let tags = r#"{"count":763,"next":"https://hub.docker.com/next","results":[
            {"name":"2.49.3"},{"name":"3.3.1-arm64"},{"name":"3.3.0"},{"name":"3.4.0"},
            {"name":"13.3.0"},{"name":"latest"}]}"#;
        assert_eq!(newest_of(tags, 3), (Some((3, 4, 0)), true));
        assert_eq!(newest_of(tags, 2), (Some((2, 49, 3)), true));
        assert_eq!(newest_of(r#"{"next":null,"results":[]}"#, 3), (None, false));
        assert_eq!(newest_of("<html>", 3), (None, false));
    }
}
