//! The project hierarchy for the health dashboard (`dviscope.hierarchy/1`): a tree of
//! areas (for example `SoC` → subsystems → blocks, any depth up to [`MAX_DEPTH`]) and the
//! regression streams attached to them. A stream (producer × suite × repository-qualified
//! branch) has exactly one *home* node and may be *linked* under other nodes (a reused
//! block); every roll-up counts it once.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Schema identifier.
pub const HIERARCHY: &str = "dviscope.hierarchy/1";
/// Deepest path (segments).
pub const MAX_DEPTH: usize = 8;
/// Most nodes in a tree.
pub const MAX_NODES: usize = 2_000;
/// Most stream attachments (homes and links) in a tree.
pub const MAX_ATTACHMENTS: usize = 10_000;

/// A hierarchy file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hierarchy {
    /// `dviscope.hierarchy/1` (optional in files; checked when present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Nodes, parents before children; the order among siblings is the display order.
    pub nodes: Vec<Node>,
    /// Streams and their home node.
    #[serde(default)]
    pub streams: Vec<StreamHome>,
    /// Reuse: a stream shown under another node too.
    #[serde(default)]
    pub links: Vec<StreamLink>,
}

/// A node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Path: `/`-separated segments of `[a-z0-9_-]`, 1–64 characters each (`soc/cpu_ss`).
    pub path: String,
    /// Display title (default: the last segment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// A stream's identity.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct StreamRef {
    /// Producer (collector) name.
    pub producer: String,
    /// Suite.
    pub suite: String,
    /// Repository-qualified branch, `repo/name`.
    pub branch: String,
}

/// A stream at its home node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamHome {
    /// Home node path.
    pub node: String,
    /// Producer name.
    pub producer: String,
    /// Suite.
    pub suite: String,
    /// Repository-qualified branch, `repo/name`.
    pub branch: String,
    /// Expected cadence: `nightly` (24 h), `weekly` (168 h), `<N>h`, or `none` (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cadence: Option<String>,
}

impl StreamHome {
    /// The stream's identity.
    #[must_use]
    pub fn stream(&self) -> StreamRef {
        StreamRef {
            producer: self.producer.clone(),
            suite: self.suite.clone(),
            branch: self.branch.clone(),
        }
    }
}

/// A stream linked under another node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamLink {
    /// Node path where it is also shown.
    pub node: String,
    /// The stream (it must have a home).
    pub stream: StreamRef,
}

/// A validation problem, located by the file's field path (`streams[3].node`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Where.
    pub at: String,
    /// What.
    pub message: String,
}

fn segment_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// The parent path of a node (`None` for a root).
#[must_use]
pub fn parent(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(p, _)| p)
}

/// Cadence in hours (`None` = never overdue), or an error message.
///
/// # Errors
/// An unknown spelling or a zero/oversized number of hours.
pub fn cadence_hours(c: Option<&str>) -> Result<Option<i32>, String> {
    match c {
        None | Some("none") => Ok(None),
        Some("nightly" | "daily") => Ok(Some(24)),
        Some("weekly") => Ok(Some(168)),
        Some(s) => s
            .strip_suffix('h')
            .and_then(|n| n.parse::<i32>().ok())
            .filter(|n| (1..=24 * 366).contains(n))
            .map(Some)
            .ok_or_else(|| format!("cadence {s:?}: use nightly, weekly, <N>h (1..8784) or none")),
    }
}

/// Splits `repo/name` (the repository is the first segment).
#[must_use]
pub fn split_branch(b: &str) -> Option<(&str, &str)> {
    b.split_once('/')
        .filter(|(r, n)| !r.is_empty() && !n.is_empty())
}

impl Hierarchy {
    /// Every problem of the file (empty when valid). Producers are checked by the server.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one pass per section, every problem located
    pub fn validate(&self) -> Vec<Problem> {
        let mut out = vec![];
        let mut p = |at: String, m: String| out.push(Problem { at, message: m });
        if let Some(s) = &self.schema
            && s != HIERARCHY
        {
            p("schema".into(), format!("schema must be {HIERARCHY}"));
        }
        if self.nodes.is_empty() {
            p("nodes".into(), "at least one node".into());
        }
        if self.nodes.len() > MAX_NODES {
            p("nodes".into(), format!("at most {MAX_NODES} nodes"));
        }
        if self.streams.len() + self.links.len() > MAX_ATTACHMENTS {
            p(
                "streams".into(),
                format!("at most {MAX_ATTACHMENTS} streams and links together"),
            );
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for (i, n) in self.nodes.iter().enumerate() {
            let at = format!("nodes[{i}].path");
            let segs: Vec<&str> = n.path.split('/').collect();
            if !segs.iter().all(|s| segment_ok(s)) {
                p(
                    at.clone(),
                    format!(
                        "{:?}: segments of a-z, 0-9, _ or -, 1 to 64 characters",
                        n.path
                    ),
                );
            } else if segs.len() > MAX_DEPTH {
                p(
                    at.clone(),
                    format!("{:?}: at most {MAX_DEPTH} levels", n.path),
                );
            }
            if let Some(par) = parent(&n.path)
                && !seen.contains(par)
            {
                p(
                    at.clone(),
                    format!("{:?}: its parent {par:?} must be listed before it", n.path),
                );
            }
            if !seen.insert(&n.path) {
                p(at, format!("{:?} is listed twice", n.path));
            }
            if let Some(t) = &n.title
                && (t.trim().is_empty()
                    || t.chars().count() > 200
                    || t.chars().any(char::is_control))
            {
                p(
                    format!("nodes[{i}].title"),
                    "a title of 1 to 200 printable characters".into(),
                );
            }
        }
        let mut homes: BTreeMap<StreamRef, usize> = BTreeMap::new();
        for (i, s) in self.streams.iter().enumerate() {
            if !seen.contains(s.node.as_str()) {
                p(
                    format!("streams[{i}].node"),
                    format!("unknown node {:?}", s.node),
                );
            }
            for (f, v) in [("producer", &s.producer), ("suite", &s.suite)] {
                if v.is_empty() || v.len() > 200 || v.chars().any(char::is_control) {
                    p(
                        format!("streams[{i}].{f}"),
                        format!("{f}: 1 to 200 printable characters"),
                    );
                }
            }
            if split_branch(&s.branch).is_none() {
                p(
                    format!("streams[{i}].branch"),
                    format!("{:?}: a repository-qualified branch, repo/name", s.branch),
                );
            }
            if let Err(m) = cadence_hours(s.cadence.as_deref()) {
                p(format!("streams[{i}].cadence"), m);
            }
            // The first home stands; a later one is the error.
            match homes.get(&s.stream()) {
                Some(first) => p(
                    format!("streams[{i}]"),
                    format!("this stream already has a home (streams[{first}]): link it instead"),
                ),
                None => {
                    homes.insert(s.stream(), i);
                }
            }
        }
        let mut attached: BTreeSet<(&str, StreamRef)> = BTreeSet::new();
        for &h in homes.values() {
            let s = &self.streams[h];
            attached.insert((s.node.as_str(), s.stream()));
        }
        for (i, l) in self.links.iter().enumerate() {
            if !seen.contains(l.node.as_str()) {
                p(
                    format!("links[{i}].node"),
                    format!("unknown node {:?}", l.node),
                );
            }
            match homes.get(&l.stream) {
                None => p(
                    format!("links[{i}].stream"),
                    "a linked stream needs a home in streams".into(),
                ),
                Some(h) if self.streams[*h].node == l.node => {
                    p(
                        format!("links[{i}].node"),
                        "a stream is not linked at its own home".into(),
                    );
                }
                Some(_) => {}
            }
            if !attached.insert((l.node.as_str(), l.stream.clone())) {
                p(
                    format!("links[{i}]"),
                    "this stream is already shown at this node".into(),
                );
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(p: &str) -> Node {
        Node {
            path: p.into(),
            title: None,
        }
    }

    fn home(node: &str, suite: &str) -> StreamHome {
        StreamHome {
            node: node.into(),
            producer: "pilot".into(),
            suite: suite.into(),
            branch: "soc/main".into(),
            cadence: Some("nightly".into()),
        }
    }

    fn sref(suite: &str) -> StreamRef {
        StreamRef {
            producer: "pilot".into(),
            suite: suite.into(),
            branch: "soc/main".into(),
        }
    }

    fn valid() -> Hierarchy {
        Hierarchy {
            schema: Some(HIERARCHY.into()),
            nodes: ["soc", "soc/cpu_ss", "soc/cpu_ss/dma", "soc/dsp_ss"]
                .map(node)
                .to_vec(),
            streams: vec![
                home("soc/cpu_ss/dma", "dma-nightly"),
                home("soc/cpu_ss", "cpu-nightly"),
            ],
            links: vec![StreamLink {
                node: "soc/dsp_ss".into(),
                stream: sref("dma-nightly"),
            }],
        }
    }

    fn problems(h: &Hierarchy) -> Vec<String> {
        h.validate()
            .into_iter()
            .map(|p| format!("{}: {}", p.at, p.message))
            .collect()
    }

    #[test]
    fn a_valid_tree() {
        assert_eq!(problems(&valid()), Vec::<String>::new());
    }

    #[test]
    fn every_problem_is_located() {
        let mut h = valid();
        h.nodes.push(node("soc/Bad Name"));
        h.nodes.push(node("orphan/child"));
        h.nodes.push(node("soc"));
        h.nodes.push(node(&["a"; 9].join("/")));
        h.streams.push(home("soc/missing", "x"));
        h.streams.push(home("soc/dsp_ss", "dma-nightly"));
        h.streams.push(StreamHome {
            branch: "main".into(),
            cadence: Some("hourly".into()),
            ..home("soc", "y")
        });
        h.links.push(StreamLink {
            node: "soc/cpu_ss/dma".into(),
            stream: sref("dma-nightly"),
        });
        h.links.push(StreamLink {
            node: "soc/dsp_ss".into(),
            stream: sref("dma-nightly"),
        });
        h.links.push(StreamLink {
            node: "soc".into(),
            stream: sref("nowhere"),
        });
        let p = problems(&h);
        let has = |at: &str, m: &str| p.iter().any(|x| x.starts_with(at) && x.contains(m));
        assert!(has("nodes[4].path", "segments"), "{p:#?}");
        assert!(has("nodes[5].path", "parent \"orphan\""), "{p:#?}");
        assert!(has("nodes[6].path", "listed twice"), "{p:#?}");
        assert!(has("nodes[7].path", "parent"), "{p:#?}");
        assert!(has("streams[2].node", "unknown node"), "{p:#?}");
        assert!(has("streams[3]", "already has a home"), "{p:#?}");
        assert!(has("streams[4].branch", "repo/name"), "{p:#?}");
        assert!(has("streams[4].cadence", "nightly, weekly"), "{p:#?}");
        assert!(has("links[1].node", "own home"), "{p:#?}");
        assert!(has("links[2]", "already shown"), "{p:#?}");
        assert!(has("links[3].stream", "needs a home"), "{p:#?}");
    }

    #[test]
    fn depth_and_cadence() {
        let mut h = valid();
        let mut path = "soc".to_string();
        for i in 1..MAX_DEPTH {
            path = format!("{path}/l{i}");
            h.nodes.push(node(&path));
        }
        assert!(problems(&h).is_empty(), "{MAX_DEPTH} levels are allowed");
        h.nodes.push(node(&format!("{path}/too_deep")));
        assert!(problems(&h).iter().any(|x| x.contains("at most 8 levels")));
        assert_eq!(cadence_hours(Some("12h")), Ok(Some(12)));
        assert_eq!(cadence_hours(Some("weekly")), Ok(Some(168)));
        assert_eq!(cadence_hours(None), Ok(None));
        assert!(cadence_hours(Some("0h")).is_err());
        assert!(cadence_hours(Some("8785h")).is_err());
    }
}
