//! Reads the state of the n8n cluster from its Redis: the job queue, Redis'
//! own health, and the members n8n registers there with a heartbeat.
//!
//! Only read commands are sent (AUTH, SELECT, LLEN, ZCARD, SMEMBERS, MGET,
//! INFO), over a small RESP client so the binary carries no Redis library.

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Where the n8n Redis is and which keys n8n uses in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub db: u32,
    /// `QUEUE_BULL_PREFIX` in n8n.
    pub bull_prefix: String,
    /// The Bull queue n8n enqueues executions on.
    pub queue_name: String,
    /// `N8N_REDIS_KEY_PREFIX` in n8n.
    pub key_prefix: String,
}

impl RedisConfig {
    /// Parses `redis://[user:password@]host[:port][/db]`. The password may be
    /// percent-encoded.
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("redis://")
            .ok_or("NBUDDYN_REDIS_URL must start with redis://")?;
        let (auth, location) = match rest.rsplit_once('@') {
            Some((auth, location)) => (Some(auth), location),
            None => (None, rest),
        };
        let (host_port, db) = match location.split_once('/') {
            Some((host_port, db)) if !db.is_empty() => (
                host_port,
                db.parse()
                    .map_err(|_| "the Redis database must be a number")?,
            ),
            Some((host_port, _)) => (host_port, 0),
            None => (location, 0),
        };
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse()
                    .map_err(|_| "the Redis port must be a number")?,
            ),
            None => (host_port, 6379),
        };
        if host.is_empty() {
            return Err("NBUDDYN_REDIS_URL has no host".into());
        }
        let (username, password) = match auth {
            None => (None, None),
            Some(auth) => match auth.split_once(':') {
                Some((user, pass)) => (
                    Some(percent_decode(user)).filter(|u| !u.is_empty()),
                    Some(percent_decode(pass)).filter(|p| !p.is_empty()),
                ),
                None => (None, Some(percent_decode(auth)).filter(|p| !p.is_empty())),
            },
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            username,
            password,
            db,
            bull_prefix: "bull".into(),
            queue_name: "jobs".into(),
            key_prefix: "n8n".into(),
        })
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'%')
            .then(|| text.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Queue {
    pub waiting: i64,
    pub active: i64,
    pub delayed: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedisHealth {
    pub used_memory: i64,
    /// 0 means Redis has no memory limit.
    pub max_memory: i64,
    pub eviction_policy: String,
    pub evicted_keys: i64,
}

/// A process n8n registered in Redis and is still refreshing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Member {
    /// `main`, `worker` or `webhook`.
    pub kind: String,
    pub host_id: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cluster {
    pub queue: Queue,
    pub redis: RedisHealth,
    pub members: Vec<Member>,
}

impl Cluster {
    pub fn count(&self, kind: &str) -> usize {
        self.members.iter().filter(|m| m.kind == kind).count()
    }

    /// Distinct n8n versions among the members, sorted.
    pub fn versions(&self) -> Vec<&str> {
        let mut versions: Vec<&str> = self
            .members
            .iter()
            .map(|m| m.version.as_str())
            .filter(|v| !v.is_empty())
            .collect();
        versions.sort_unstable();
        versions.dedup();
        versions
    }
}

const TIMEOUT: Duration = Duration::from_secs(5);

pub async fn read_cluster(config: &RedisConfig) -> Result<Cluster, String> {
    tokio::time::timeout(TIMEOUT, read(config))
        .await
        .map_err(|_| format!("Redis did not answer within {} seconds", TIMEOUT.as_secs()))?
}

async fn read(config: &RedisConfig) -> Result<Cluster, String> {
    let stream = TcpStream::connect((config.host.as_str(), config.port))
        .await
        .map_err(|e| {
            format!(
                "cannot connect to Redis at {}:{}: {e}",
                config.host, config.port
            )
        })?;
    let mut conn = Connection {
        stream: BufReader::new(stream),
    };

    if let Some(password) = &config.password {
        match &config.username {
            Some(user) => conn.command(&["AUTH", user, password]).await?,
            None => conn.command(&["AUTH", password]).await?,
        };
    }
    if config.db != 0 {
        conn.command(&["SELECT", &config.db.to_string()]).await?;
    }

    let queue_key = |part: &str| format!("{}:{}:{part}", config.bull_prefix, config.queue_name);
    let queue = Queue {
        waiting: conn.command(&["LLEN", &queue_key("wait")]).await?.as_int(),
        active: conn
            .command(&["LLEN", &queue_key("active")])
            .await?
            .as_int(),
        delayed: conn
            .command(&["ZCARD", &queue_key("delayed")])
            .await?
            .as_int(),
        failed: conn
            .command(&["ZCARD", &queue_key("failed")])
            .await?
            .as_int(),
    };

    let info = conn.command(&["INFO"]).await?.into_text();
    let redis = parse_info(&info);

    let members_key = format!("{}:{{instance:}}members", config.key_prefix);
    let member_keys = conn
        .command(&["SMEMBERS", &members_key])
        .await?
        .into_strings();
    let members = if member_keys.is_empty() {
        Vec::new()
    } else {
        let mut mget: Vec<&str> = vec!["MGET"];
        mget.extend(member_keys.iter().map(String::as_str));
        // A key that expired answers nil: that member stopped refreshing.
        conn.command(&mget)
            .await?
            .into_strings()
            .iter()
            .filter_map(|j| parse_member(j))
            .collect()
    };

    Ok(Cluster {
        queue,
        redis,
        members,
    })
}

fn parse_info(info: &str) -> RedisHealth {
    let field = |name: &str| {
        info.lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix(':'))
            })
            .map(str::trim)
    };
    let number = |name: &str| field(name).and_then(|v| v.parse().ok()).unwrap_or(0);
    RedisHealth {
        used_memory: number("used_memory"),
        max_memory: number("maxmemory"),
        eviction_policy: field("maxmemory_policy").unwrap_or_default().to_owned(),
        evicted_keys: number("evicted_keys"),
    }
}

fn parse_member(json: &str) -> Option<Member> {
    let value: Value = serde_json::from_str(json).ok()?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let kind = text("instanceType");
    (!kind.is_empty()).then(|| Member {
        kind,
        host_id: text("hostId"),
        version: text("version"),
    })
}

/// One reply in the Redis protocol.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Text(String),
    Int(i64),
    Nil,
    Array(Vec<Reply>),
}

impl Reply {
    fn as_int(&self) -> i64 {
        match self {
            Reply::Int(n) => *n,
            _ => 0,
        }
    }

    fn into_text(self) -> String {
        match self {
            Reply::Text(text) => text,
            _ => String::new(),
        }
    }

    /// The text elements of an array reply, skipping nils.
    fn into_strings(self) -> Vec<String> {
        match self {
            Reply::Array(items) => items
                .into_iter()
                .filter_map(|item| match item {
                    Reply::Text(text) => Some(text),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

struct Connection {
    stream: BufReader<TcpStream>,
}

impl Connection {
    async fn command(&mut self, parts: &[&str]) -> Result<Reply, String> {
        let mut request = format!("*{}\r\n", parts.len()).into_bytes();
        for part in parts {
            request.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
            request.extend_from_slice(part.as_bytes());
            request.extend_from_slice(b"\r\n");
        }
        let io = |e: std::io::Error| format!("Redis connection failed: {e}");
        self.stream
            .get_mut()
            .write_all(&request)
            .await
            .map_err(io)?;
        read_reply(&mut self.stream).await
    }
}

/// Reads one reply. An error reply from Redis becomes `Err` with its message.
async fn read_reply<R>(reader: &mut R) -> Result<Reply, String>
where
    R: AsyncBufReadExt + Unpin,
{
    // Arrays nest (an array of bulk strings), so collect them without recursion.
    let mut stack: Vec<(usize, Vec<Reply>)> = Vec::new();
    loop {
        let io = |e: std::io::Error| format!("Redis connection failed: {e}");
        let mut line = String::new();
        if reader.read_line(&mut line).await.map_err(io)? == 0 {
            return Err("Redis closed the connection".into());
        }
        let line = line.trim_end();
        let (kind, rest) = line.split_at(line.len().min(1));
        let length = || {
            rest.parse::<i64>()
                .map_err(|_| format!("unexpected Redis reply: {line}"))
        };

        let mut reply = match kind {
            "+" => Reply::Text(rest.to_owned()),
            "-" => return Err(format!("Redis refused the command: {rest}")),
            ":" => Reply::Int(length()?),
            "$" => match length()? {
                n if n < 0 => Reply::Nil,
                n => {
                    let mut body = vec![0u8; n as usize + 2];
                    reader.read_exact(&mut body).await.map_err(io)?;
                    body.truncate(n as usize);
                    Reply::Text(String::from_utf8_lossy(&body).into_owned())
                }
            },
            "*" => match length()? {
                n if n < 0 => Reply::Nil,
                0 => Reply::Array(Vec::new()),
                n => {
                    stack.push((n as usize, Vec::with_capacity(n as usize)));
                    continue;
                }
            },
            _ => return Err(format!("unexpected Redis reply: {line}")),
        };

        // Hand the finished reply to the array waiting for it, closing every
        // array this completes.
        loop {
            match stack.last_mut() {
                None => return Ok(reply),
                Some((wanted, items)) => {
                    items.push(reply);
                    if items.len() < *wanted {
                        break;
                    }
                    let (_, items) = stack.pop().expect("an array is open");
                    reply = Reply::Array(items);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8]) -> Result<Reply, String> {
        read_reply(&mut BufReader::new(bytes)).await
    }

    fn text(s: &str) -> Reply {
        Reply::Text(s.into())
    }

    #[tokio::test]
    async fn replies_of_every_kind_are_parsed() {
        assert_eq!(parse(b"+OK\r\n").await, Ok(text("OK")));
        assert_eq!(parse(b":42\r\n").await, Ok(Reply::Int(42)));
        assert_eq!(parse(b"$5\r\nhello\r\n").await, Ok(text("hello")));
        assert_eq!(parse(b"$-1\r\n").await, Ok(Reply::Nil));
        assert_eq!(parse(b"*0\r\n").await, Ok(Reply::Array(vec![])));
        assert_eq!(
            parse(b"*3\r\n$1\r\na\r\n$-1\r\n:7\r\n").await,
            Ok(Reply::Array(vec![text("a"), Reply::Nil, Reply::Int(7)]))
        );
        assert_eq!(
            parse(b"*2\r\n*1\r\n$1\r\nx\r\n$1\r\ny\r\n").await,
            Ok(Reply::Array(vec![Reply::Array(vec![text("x")]), text("y")]))
        );
    }

    #[tokio::test]
    async fn bulk_text_may_contain_line_breaks() {
        assert_eq!(
            parse(b"$9\r\na:1\r\nb:22\r\n").await,
            Ok(text("a:1\r\nb:22"))
        );
    }

    #[tokio::test]
    async fn errors_and_broken_replies_are_reported() {
        assert_eq!(
            parse(b"-WRONGPASS invalid username-password pair\r\n").await,
            Err("Redis refused the command: WRONGPASS invalid username-password pair".into())
        );
        assert_eq!(parse(b"").await, Err("Redis closed the connection".into()));
        assert!(parse(b"?what\r\n").await.is_err());
    }

    #[test]
    fn redis_urls_are_parsed() {
        let plain = RedisConfig::parse("redis://n8n_redis").unwrap();
        assert_eq!(
            (plain.host.as_str(), plain.port, plain.db),
            ("n8n_redis", 6379, 0)
        );
        assert_eq!((plain.username, plain.password), (None, None));

        let full = RedisConfig::parse("redis://:S3cret%21%40x@cache.internal:6380/2").unwrap();
        assert_eq!(
            (full.host.as_str(), full.port, full.db),
            ("cache.internal", 6380, 2)
        );
        assert_eq!(full.password.as_deref(), Some("S3cret!@x"));
        assert_eq!(full.username, None);

        let acl = RedisConfig::parse("redis://watcher:pw@h:1").unwrap();
        assert_eq!(
            (acl.username.as_deref(), acl.password.as_deref()),
            (Some("watcher"), Some("pw"))
        );

        assert!(RedisConfig::parse("http://h").is_err());
        assert!(RedisConfig::parse("redis://h:port").is_err());
        assert!(RedisConfig::parse("redis://").is_err());
    }

    #[test]
    fn info_fields_are_read_by_exact_name() {
        let info =
            "# Memory\r\nused_memory:6651904\r\nused_memory_human:6.34M\r\nmaxmemory:943718400\r\n\
                    maxmemory_policy:allkeys-lru\r\n# Stats\r\nevicted_keys:3\r\n";
        assert_eq!(
            parse_info(info),
            RedisHealth {
                used_memory: 6_651_904,
                max_memory: 943_718_400,
                eviction_policy: "allkeys-lru".into(),
                evicted_keys: 3,
            }
        );
        assert_eq!(parse_info(""), RedisHealth::default());
    }

    #[test]
    fn members_are_read_from_their_registration() {
        let member = parse_member(
            r#"{"instanceType":"worker","hostId":"worker-ab12","version":"3.3.0","x":1}"#,
        );
        assert_eq!(
            member,
            Some(Member {
                kind: "worker".into(),
                host_id: "worker-ab12".into(),
                version: "3.3.0".into()
            })
        );
        assert_eq!(parse_member("not json"), None);
        assert_eq!(parse_member(r#"{"hostId":"x"}"#), None);
    }

    #[test]
    fn cluster_counts_members_and_versions() {
        let member = |kind: &str, version: &str| Member {
            kind: kind.into(),
            host_id: String::new(),
            version: version.into(),
        };
        let cluster = Cluster {
            members: vec![
                member("main", "3.3.0"),
                member("worker", "3.3.0"),
                member("worker", "3.2.2"),
            ],
            ..Cluster::default()
        };
        assert_eq!((cluster.count("worker"), cluster.count("webhook")), (2, 0));
        assert_eq!(cluster.versions(), vec!["3.2.2", "3.3.0"]);
    }
}
