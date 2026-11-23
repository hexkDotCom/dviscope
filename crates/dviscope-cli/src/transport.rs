//! The server transport of `spool flush` (`docs/journal.md`, `docs/api.md`): ingest records
//! travel as NDJSON batches bounded by count and bytes; regression and manifest operations
//! go to their own routes. Status handling: a receipt commits; 400, 404, 409, 410, 413 and
//! 422 reject that record; 401 and 403 stop the flush; 429, 5xx, network errors and
//! anything unreadable leave the record pending (replay is safe).

use reqwest::{Method, StatusCode, Url};
use serde_json::Value;

use crate::spool::{BatchError, Outgoing, Response, Transport};

/// Bytes of one NDJSON request body (the server accepts 8 MiB encoded).
pub const MAX_BATCH_BYTES: usize = 6 * 1024 * 1024;
/// Records of one NDJSON request.
pub const MAX_BATCH_RECORDS: usize = 1_000;

/// Record kinds delivered through `/api/v1/ingest`.
const INGEST_PREFIXES: &[&str] = &[
    "attempt_started:",
    "simulation_attempt:",
    "build_started:",
    "build_attempt:",
];

/// The HTTP transport. `deliver` blocks on the given runtime handle (call it from a
/// blocking thread, e.g. `spawn_blocking`).
#[derive(Debug)]
pub struct HttpTransport {
    client: reqwest::Client,
    base: Url,
    token: String,
    rt: tokio::runtime::Handle,
    deadline: Option<std::time::Instant>,
}

impl HttpTransport {
    /// A transport for `base` (an `https://` origin checked by [`crate::client::build`]).
    ///
    /// # Errors
    /// An unparseable base URL.
    pub fn new(
        client: reqwest::Client,
        base: &str,
        token: String,
        rt: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        let base = Url::parse(base).map_err(|_| "invalid server URL".to_string())?;
        Ok(Self {
            client,
            base,
            token,
            rt,
            deadline: None,
        })
    }

    /// Bounds every delivery by an absolute deadline: past it nothing is sent, and a batch
    /// still in flight when it passes is abandoned (its records stay pending; at-least-once
    /// delivery replays them later).
    #[must_use]
    pub fn with_deadline(mut self, deadline: Option<std::time::Instant>) -> Self {
        self.deadline = deadline;
        self
    }
}

/// The ingest route under the server URL, its path prefix kept (a server behind a proxy at
/// `https://host/dviscope`), as every other route.
fn ingest_url(base: &Url) -> Option<Url> {
    let mut url = base.clone();
    {
        let mut p = url.path_segments_mut().ok()?;
        p.pop_if_empty();
        p.extend(["api", "v1", "ingest"]);
    }
    Some(url)
}

/// The route of a regression or manifest operation, from its identity.
fn route(base: &Url, identity: &str) -> Option<(Method, Url)> {
    let (kind, rest) = identity.split_once(':')?;
    let mut url = base.clone();
    let mut segs = |parts: &[&str]| -> Option<()> {
        let mut p = url.path_segments_mut().ok()?;
        p.pop_if_empty();
        for s in parts {
            p.push(s);
        }
        Some(())
    };
    let method = match kind {
        "source_manifest" => {
            segs(&["api", "v1", "source-manifests"])?;
            Method::POST
        }
        "regression" => {
            segs(&["api", "v1", "regressions"])?;
            Method::POST
        }
        "manifest_chunk" => {
            let (r, n) = rest.rsplit_once('/')?;
            segs(&["api", "v1", "regressions", r, "manifest", "chunks", n])?;
            Method::PUT
        }
        "manifest_seal" => {
            segs(&["api", "v1", "regressions", rest, "manifest", "seal"])?;
            Method::POST
        }
        "manifest_amend" => {
            let (r, _) = rest.rsplit_once('/')?;
            segs(&["api", "v1", "regressions", r, "manifest", "amend"])?;
            Method::POST
        }
        "slot_mark" => {
            let (r, _) = rest.rsplit_once('/')?;
            segs(&["api", "v1", "regressions", r, "slots", "mark"])?;
            Method::POST
        }
        "finish" => {
            segs(&["api", "v1", "regressions", rest, "finish"])?;
            Method::POST
        }
        _ => return None,
    };
    Some((method, url))
}

/// One record's answer from its HTTP status and body.
fn answer(status: u16, body: Value) -> Result<Response, BatchError> {
    match status {
        200..=299 => Ok(Response::Committed(body)),
        401 | 403 => Err(BatchError::Auth(status)),
        400 | 404 | 409 | 410 | 413 | 422 => Ok(Response::Rejected {
            status,
            error: body,
        }),
        _ => Ok(Response::Retry),
    }
}

impl HttpTransport {
    async fn send(
        &self,
        method: Method,
        url: Url,
        body: Vec<u8>,
        ndjson: bool,
    ) -> Result<(u16, String), BatchError> {
        let res = self
            .client
            .request(method, url)
            .bearer_auth(&self.token)
            .header(
                reqwest::header::CONTENT_TYPE,
                if ndjson {
                    "application/x-ndjson"
                } else {
                    "application/json"
                },
            )
            .body(body)
            .send()
            .await
            .map_err(|e| BatchError::Transient(format!("request failed: {}", e.without_url())))?;
        let status = res.status().as_u16();
        let text = res
            .text()
            .await
            .map_err(|e| BatchError::Transient(format!("response lost: {}", e.without_url())))?;
        Ok((status, text))
    }

    async fn ingest(&self, batch: &[&Outgoing]) -> Result<Vec<Response>, BatchError> {
        let mut body = Vec::new();
        for o in batch {
            serde_json::to_writer(&mut body, &o.body)
                .map_err(|e| BatchError::Transient(e.to_string()))?;
            body.push(b'\n');
        }
        let url = ingest_url(&self.base)
            .ok_or_else(|| BatchError::Transient("the server URL cannot carry a path".into()))?;
        let (status, text) = self.send(Method::POST, url, body, true).await?;
        if status == StatusCode::OK.as_u16() {
            let mut out = vec![Response::Retry; batch.len()];
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let Some(i) = v["line"].as_u64().and_then(|n| usize::try_from(n).ok()) else {
                    continue;
                };
                let Some(slot) = i.checked_sub(1).and_then(|i| out.get_mut(i)) else {
                    continue;
                };
                *slot = match v["result"].as_str() {
                    Some("committed" | "duplicate") => Response::Committed(v["receipt"].clone()),
                    Some("rejected") => {
                        let st = u16::try_from(v["status"].as_u64().unwrap_or(400)).unwrap_or(400);
                        match st {
                            // A record-level 401/403 (another producer's record) is a
                            // permanent rejection of that record, not a credential stop.
                            401 | 403 => Response::Rejected {
                                status: st,
                                error: v["error"].clone(),
                            },
                            s => answer(s, v["error"].clone()).unwrap_or(Response::Retry),
                        }
                    }
                    _ => Response::Retry,
                };
            }
            return Ok(out);
        }
        let err: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        match status {
            401 | 403 => Err(BatchError::Auth(status)),
            // The batch as a whole was refused (size): every record waits; batches are cut
            // smaller than the server's limits, so this does not repeat for valid data.
            413 => Ok(vec![Response::Retry; batch.len()]),
            400 => Ok(batch
                .iter()
                .map(|_| Response::Rejected {
                    status,
                    error: err.clone(),
                })
                .collect()),
            _ => Ok(vec![Response::Retry; batch.len()]),
        }
    }

    async fn deliver_async(&self, batch: &[Outgoing]) -> Result<Vec<Response>, BatchError> {
        let mut out: Vec<Option<Response>> = vec![None; batch.len()];
        // Operations first (regressions and manifests are what attempts refer to), one
        // request each.
        for (i, o) in batch.iter().enumerate() {
            if INGEST_PREFIXES.iter().any(|p| o.identity.starts_with(p)) {
                continue;
            }
            let Some((method, url)) = route(&self.base, &o.identity) else {
                out[i] = Some(Response::Rejected {
                    status: 0,
                    error: serde_json::json!({"code": "E_LOCAL_UNROUTABLE",
                        "message": "no server route for this record kind"}),
                });
                continue;
            };
            let body =
                serde_json::to_vec(&o.body).map_err(|e| BatchError::Transient(e.to_string()))?;
            let (status, text) = self.send(method, url, body, false).await?;
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            out[i] = Some(answer(status, v)?);
        }
        // Ingest records: NDJSON requests bounded by count and bytes, in journal order.
        let ingest: Vec<usize> = (0..batch.len())
            .filter(|i| {
                INGEST_PREFIXES
                    .iter()
                    .any(|p| batch[*i].identity.starts_with(p))
            })
            .collect();
        let mut group: Vec<usize> = vec![];
        let mut bytes = 0usize;
        let mut groups: Vec<Vec<usize>> = vec![];
        for i in ingest {
            let n = serde_json::to_vec(&batch[i].body).map_or(0, |v| v.len()) + 1;
            if !group.is_empty()
                && (group.len() >= MAX_BATCH_RECORDS || bytes + n > MAX_BATCH_BYTES)
            {
                groups.push(std::mem::take(&mut group));
                bytes = 0;
            }
            group.push(i);
            bytes += n;
        }
        if !group.is_empty() {
            groups.push(group);
        }
        for g in groups {
            let recs: Vec<&Outgoing> = g.iter().map(|i| &batch[*i]).collect();
            for (i, r) in g.iter().zip(self.ingest(&recs).await?) {
                out[*i] = Some(r);
            }
        }
        Ok(out
            .into_iter()
            .map(|r| r.unwrap_or(Response::Retry))
            .collect())
    }
}

impl Transport for HttpTransport {
    fn deliver(&mut self, batch: &[Outgoing]) -> Result<Vec<Response>, BatchError> {
        let rt = self.rt.clone();
        let Some(t) = self.deadline else {
            return rt.block_on(self.deliver_async(batch));
        };
        let Some(left) = t
            .checked_duration_since(std::time::Instant::now())
            .filter(|l| !l.is_zero())
        else {
            return Err(BatchError::Transient("the deadline passed".into()));
        };
        rt.block_on(async { tokio::time::timeout(left, self.deliver_async(batch)).await })
            .unwrap_or_else(|_| {
                Err(BatchError::Transient(
                    "the deadline passed during a request".into(),
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ingest keeps the server URL's path prefix, as the other routes do.
    #[test]
    fn ingest_keeps_the_path_prefix() {
        for (base, want) in [
            ("https://h:8443", "/api/v1/ingest"),
            ("https://h:8443/", "/api/v1/ingest"),
            ("https://h/dviscope", "/dviscope/api/v1/ingest"),
            ("https://h/dviscope/", "/dviscope/api/v1/ingest"),
        ] {
            let u = Url::parse(base).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                ingest_url(&u).map(|u| u.path().to_string()).as_deref(),
                Some(want),
                "{base}"
            );
            let r = route(&u, "regression:r1").map(|(_, u)| u.path().to_string());
            assert_eq!(r, Some(want.replace("ingest", "regressions")), "{base}");
        }
    }

    #[test]
    fn routes_encode_references() {
        let base = Url::parse("https://127.0.0.1:8443").unwrap_or_else(|e| panic!("{e}"));
        let r = |id: &str| route(&base, id).map(|(m, u)| format!("{m} {}", u.path()));
        assert_eq!(
            r("manifest_chunk:nightly/2026-11-08/3").as_deref(),
            Some("PUT /api/v1/regressions/nightly%2F2026-11-08/manifest/chunks/3")
        );
        assert_eq!(
            r("regression:r1").as_deref(),
            Some("POST /api/v1/regressions")
        );
        assert_eq!(
            r("finish:r1").as_deref(),
            Some("POST /api/v1/regressions/r1/finish")
        );
        assert_eq!(
            r("slot_mark:r1/abc").as_deref(),
            Some("POST /api/v1/regressions/r1/slots/mark")
        );
        assert!(r("attempt_started:a1").is_none());
    }

    #[test]
    fn statuses() {
        assert!(matches!(
            answer(201, Value::Null),
            Ok(Response::Committed(_))
        ));
        assert!(matches!(
            answer(409, Value::Null),
            Ok(Response::Rejected { status: 409, .. })
        ));
        assert!(matches!(
            answer(401, Value::Null),
            Err(BatchError::Auth(401))
        ));
        assert!(matches!(answer(503, Value::Null), Ok(Response::Retry)));
        assert!(matches!(answer(500, Value::Null), Ok(Response::Retry)));
    }
}
