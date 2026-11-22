//! The smallest HTTP client that can deliver an alert: one JSON POST over
//! http or https, and the status that came back. Written by hand, like the
//! Redis and runner clients, so the binary carries no HTTP library.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tls::{self, Trust};

const TIMEOUT: Duration = Duration::from_secs(10);
/// How much of an answer is read: enough for any error message.
const ANSWER_MAX: usize = 16 * 1024;

/// An `http://` or `https://` address, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

impl Target {
    pub fn parse(url: &str) -> Result<Self, String> {
        let (secure, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
            (Some(rest), _) => (true, rest),
            (None, Some(rest)) => (false, rest),
            (None, None) => return Err("the address must start with http:// or https://".into()),
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err("the address must not carry a user name".into());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| "the port must be a number")?),
            None => (authority, if secure { 443 } else { 80 }),
        };
        let valid_host = !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !valid_host || path.chars().any(|c| c.is_ascii_control() || c == ' ') {
            return Err("the address is not valid".into());
        }
        Ok(Self {
            secure,
            host: host.to_owned(),
            port,
            path: if path.starts_with('?') {
                format!("/{path}")
            } else {
                path.to_owned()
            },
        })
    }
}

/// What the server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: String,
}

/// Sends `body` as JSON and returns the answer, whatever its status.
pub async fn post_json(url: &str, body: &str) -> Result<Answer, String> {
    let target = Target::parse(url)?;
    tokio::time::timeout(TIMEOUT, send(&target, body))
        .await
        .map_err(|_| {
            format!(
                "{} did not answer in {} seconds",
                target.host,
                TIMEOUT.as_secs()
            )
        })?
}

async fn send(target: &Target, body: &str) -> Result<Answer, String> {
    let stream = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| format!("cannot connect to {}: {e}", target.host))?;
    if target.secure {
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|_| format!("{} is not a valid server name", target.host))?;
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(Trust::Verified)?));
        let stream = connector.connect(name, stream).await.map_err(|e| {
            format!(
                "cannot open an encrypted connection to {}: {e}",
                target.host
            )
        })?;
        exchange(stream, target, body).await
    } else {
        exchange(stream, target, body).await
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    target: &Target,
    body: &str,
) -> Result<Answer, String> {
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: nbuddyn\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        target.path,
        target.host,
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("cannot send: {e}"))?;

    let mut answer = Vec::new();
    let mut buffer = [0u8; 2048];
    while answer.len() < ANSWER_MAX {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => answer.extend_from_slice(&buffer[..n]),
            // A server that closes without saying goodbye still answered.
            Err(_) if !answer.is_empty() => break,
            Err(e) => return Err(format!("cannot read the answer: {e}")),
        }
    }
    parse_answer(&String::from_utf8_lossy(&answer))
}

fn parse_answer(text: &str) -> Result<Answer, String> {
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("HTTP/"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or("the server did not answer as a web server")?;
    Ok(Answer {
        status,
        body: body.chars().take(500).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn addresses_are_taken_apart() {
        let t = Target::parse("https://api.telegram.org/bot123:abc/sendMessage").unwrap();
        assert_eq!(
            (t.secure, t.host.as_str(), t.port),
            (true, "api.telegram.org", 443)
        );
        assert_eq!(t.path, "/bot123:abc/sendMessage");
        let t = Target::parse("http://n8n:5678?x=1").unwrap();
        assert_eq!((t.secure, t.port, t.path.as_str()), (false, 5678, "/?x=1"));
        assert_eq!(Target::parse("http://hooks.example.com").unwrap().path, "/");
        for bad in [
            "ftp://x",
            "https://",
            "https://user@host/x",
            "https://ho st/x",
            "https://h:port/",
        ] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn answers_are_read_whatever_their_status() {
        let ok =
            parse_answer("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}")
                .unwrap();
        assert_eq!((ok.status, ok.body.as_str()), (200, "{\"ok\":true}"));
        assert_eq!(
            parse_answer("HTTP/1.1 401 Unauthorized\r\n\r\n")
                .unwrap()
                .status,
            401
        );
        assert!(parse_answer("garbage").is_err());
    }

    #[tokio::test]
    async fn a_json_body_is_posted_and_the_answer_comes_back() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut seen = vec![0u8; 2048];
            let n = socket.read(&mut seen).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nnope")
                .await
                .unwrap();
            String::from_utf8_lossy(&seen[..n]).into_owned()
        });
        let answer = post_json(
            &format!("http://127.0.0.1:{port}/hook?x=1"),
            "{\"text\":\"hola\"}",
        )
        .await
        .unwrap();
        assert_eq!((answer.status, answer.body.as_str()), (403, "nope"));
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /hook?x=1 HTTP/1.1\r\n"));
        assert!(request.contains("Content-Length: 15\r\n"));
        assert!(request.ends_with("{\"text\":\"hola\"}"));
    }
}
