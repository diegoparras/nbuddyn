//! Asks each task runner whether it is alive.
//!
//! n8n keeps no record of its external task runners in Postgres or Redis, so
//! the only way to know is to ask. Every runner container already answers
//! `GET /healthz` for this purpose (port 5680, served by the launcher). The
//! request is written by hand so the binary carries no HTTP client.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The port the task runner launcher serves its health check on.
const DEFAULT_PORT: u16 = 5680;
const DEFAULT_PATH: &str = "/healthz";
const TIMEOUT: Duration = Duration::from_secs(3);

/// Where one runner answers its health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// The answer of one runner in one scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunnerProbe {
    pub name: String,
    /// `None` when it answered 200; otherwise why it counts as down.
    pub problem: Option<String>,
}

/// Parses a comma-separated list where each entry is `host`, `host:port` or
/// `http://host[:port][/path]`.
pub fn parse_targets(list: &str) -> Result<Vec<RunnerTarget>, String> {
    list.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(parse_target)
        .collect()
}

fn parse_target(entry: &str) -> Result<RunnerTarget, String> {
    if entry.starts_with("https://") {
        return Err(format!(
            "NBUDDYN_RUNNER_URLS: {entry} uses https, and runner health checks are plain http"
        ));
    }
    let rest = entry.strip_prefix("http://").unwrap_or(entry);
    let (host_port, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, DEFAULT_PATH),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse().map_err(|_| {
                format!("NBUDDYN_RUNNER_URLS: {entry} has a port that is not a number")
            })?,
        ),
        None => (host_port, DEFAULT_PORT),
    };
    let valid_host = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !valid_host {
        return Err(format!("NBUDDYN_RUNNER_URLS: {entry} has no valid host"));
    }
    if path.chars().any(|c| c.is_ascii_control() || c == ' ') {
        return Err(format!("NBUDDYN_RUNNER_URLS: {entry} has an invalid path"));
    }
    Ok(RunnerTarget {
        host: host.to_owned(),
        port,
        path: if path == "/" { DEFAULT_PATH } else { path }.to_owned(),
    })
}

/// Asks every runner at once and returns the answers in the configured order.
pub async fn probe_all(targets: &[RunnerTarget]) -> Vec<RunnerProbe> {
    let tasks: Vec<_> = targets
        .iter()
        .cloned()
        .map(|target| tokio::spawn(async move { probe(&target).await }))
        .collect();
    let mut probes = Vec::with_capacity(tasks.len());
    for (task, target) in tasks.into_iter().zip(targets) {
        probes.push(RunnerProbe {
            name: target.host.clone(),
            problem: match task.await {
                Ok(result) => result.err(),
                Err(_) => Some("the check did not finish".into()),
            },
        });
    }
    probes
}

async fn probe(target: &RunnerTarget) -> Result<(), String> {
    tokio::time::timeout(TIMEOUT, ask(target))
        .await
        .map_err(|_| format!("no answer in {} seconds", TIMEOUT.as_secs()))?
}

async fn ask(target: &RunnerTarget) -> Result<(), String> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| format!("cannot connect: {e}"))?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: nbuddyn\r\nConnection: close\r\n\r\n",
        target.path, target.host, target.port
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("cannot send: {e}"))?;

    // The status line is all that matters; it fits well within this buffer.
    let mut buffer = [0u8; 64];
    let mut filled = 0;
    while filled < buffer.len() && !buffer[..filled].contains(&b'\n') {
        match stream.read(&mut buffer[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(format!("cannot read: {e}")),
        }
    }
    status_of(&buffer[..filled])
}

/// Reads an HTTP status line such as `HTTP/1.1 200 OK`.
fn status_of(head: &[u8]) -> Result<(), String> {
    let line = String::from_utf8_lossy(head);
    let line = line.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let is_http = parts.next().is_some_and(|p| p.starts_with("HTTP/"));
    match parts.next().filter(|_| is_http) {
        Some("200") => Ok(()),
        Some(code) if code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) => {
            Err(format!("answered {code}"))
        }
        _ => Err("did not answer as a health check".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn target(host: &str, port: u16, path: &str) -> RunnerTarget {
        RunnerTarget {
            host: host.into(),
            port,
            path: path.into(),
        }
    }

    #[test]
    fn entries_default_to_the_launcher_port_and_path() {
        assert_eq!(
            parse_targets("n8n_runner-01, n8n_runner-02:5681 ,http://r3:9000/health,").unwrap(),
            vec![
                target("n8n_runner-01", 5680, "/healthz"),
                target("n8n_runner-02", 5681, "/healthz"),
                target("r3", 9000, "/health"),
            ]
        );
        assert_eq!(
            parse_targets("http://runner/").unwrap(),
            vec![target("runner", 5680, "/healthz")]
        );
        assert!(parse_targets("").unwrap().is_empty());
    }

    #[test]
    fn bad_entries_are_refused_with_a_reason() {
        assert!(parse_targets("https://runner")
            .unwrap_err()
            .contains("https"));
        assert!(parse_targets("runner:abc").unwrap_err().contains("port"));
        assert!(parse_targets("http://:5680").unwrap_err().contains("host"));
        assert!(parse_targets("user@runner").unwrap_err().contains("host"));
        assert!(parse_targets("runner/a b").unwrap_err().contains("path"));
    }

    #[test]
    fn only_a_200_counts_as_alive() {
        assert_eq!(status_of(b"HTTP/1.1 200 OK\r\nContent-Type"), Ok(()));
        assert_eq!(
            status_of(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Err("answered 503".into())
        );
        assert!(status_of(b"-ERR unknown command\r\n").is_err());
        assert!(status_of(b"").is_err());
    }

    /// Serves one canned answer per connection on a free local port.
    async fn serve(answer: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = [0u8; 512];
                let _ = socket.read(&mut request).await;
                let _ = socket.write_all(answer.as_bytes()).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn runners_are_asked_and_answers_keep_their_order() {
        let alive = serve("HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}").await;
        let broken = serve("HTTP/1.1 500 Internal Server Error\r\n\r\n").await;
        // A port nothing listens on: bind, note it, and close it again.
        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };

        let probes = probe_all(&[
            target("127.0.0.1", alive, "/healthz"),
            target("127.0.0.1", broken, "/healthz"),
            target("127.0.0.1", closed, "/healthz"),
        ])
        .await;

        assert_eq!(probes[0].problem, None);
        assert_eq!(probes[1].problem.as_deref(), Some("answered 500"));
        assert!(probes[2]
            .problem
            .as_deref()
            .is_some_and(|p| p.starts_with("cannot connect")));
    }
}
