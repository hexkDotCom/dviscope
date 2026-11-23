//! Source locations and UVM component paths in simulator logs (ported from DVICode's
//! `logparse.ts`): UVM report lines (the default report-server format), VCS messages whose
//! location is on the next line, elaboration-task locations, and the common `file(line)`,
//! `file:line` and `file,line|col` forms. Offsets are byte offsets into the text as written
//! (terminal escape sequences included); paths are kept exactly as written.

use std::sync::LazyLock;

use regex::Regex;

/// Bytes of a line read at most: a longer line (a dump, a huge message) is read up to there.
pub const MAX_LINE: usize = 4096;

/// What a link points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A source file and line.
    File {
        /// The path as written.
        path: String,
        /// The 1-based line.
        line: u32,
    },
    /// A UVM component path (`uvm_test_top...`).
    Component {
        /// The hierarchical path.
        path: String,
    },
}

/// A link in a line or a text: the byte range that names it, and where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Start offset (bytes).
    pub start: usize,
    /// End offset (bytes, exclusive).
    pub end: usize,
    /// The target.
    pub target: Target,
}

fn re(pattern: &str) -> Regex {
    // The patterns are constants; a failure is a programming error caught by the tests.
    Regex::new(pattern).unwrap_or_else(|e| panic!("bad built-in pattern: {e}"))
}

/// `UVM_ERROR ../tb/sb.sv(142) @ 1500: uvm_test_top.env.sb [SB] ...`, with the verbosity when
/// the report server shows it; the file part is absent in reports without one. The file may
/// hold spaces: it ends at the `(line) @` that follows it.
static UVM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\bUVM_(?:INFO|WARNING|ERROR|FATAL)(?:\([A-Z_]+\))?\s+(?:(\S[^\n]*?)\((\d+)\)\s+)?@\s*[^:\n]*?:\s+(\S+)\s+\[",
    )
});
/// `"x.sv", 12`: any extension inside quotes.
static QUOTED: LazyLock<Regex> = LazyLock::new(|| re(r#""([^"\n]+\.[A-Za-z0-9]{1,6})",\s*(\d+)"#));
/// Anchors of the forms outside quotes, the path read back from them: `x.sv(12)`, `x.sv:12`
/// and `x.sv:12:3`, `x.sv,12|3`.
static ANCHORS: LazyLock<Regex> = LazyLock::new(|| re(r"\((\d+)\)|:(\d+)\b|,(\d+)\|\d+"));
/// A message header whose location is on the next line, `path, line`.
static HEADER: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\s*(?:Error|Warning|Lint|Note|Information)-\[[^\]]*\]"));
static LOCATION: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*(\S[^,]*?),\s*(\d+)\s*$"));
/// Elaboration tasks: `location: file` / `path` / `line N`, or all on one line.
static TASK_FILE: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*location:\s*file\s*$"));
static TASK_ONE_LINE: LazyLock<Regex> =
    LazyLock::new(|| re(r"location:\s*file\s+(\S+)\s+line\s+(\d+)"));
static TASK_LINE: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*line\s+(\d+)\b"));
/// Terminal colours and other escape sequences (CSI and OSC).
static ESCAPES: LazyLock<Regex> =
    LazyLock::new(|| re("\x1b\\[[0-?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)"));
/// A line that may hold a link; most lines of a long log have none.
static MAYBE: LazyLock<Regex> = LazyLock::new(|| re(r#"[(:,"|]\s*\d|location:|UVM_"#));
/// A line of an error or a warning: its links have a budget of their own.
static SEVERE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"UVM_(?:ERROR|FATAL|WARNING)|^\s*(?:Error|Warning)[-:]|\*\* (?:Error|Warning)|\*[EWF],")
});
static SEVERE_HEADER: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*(?:Error|Warning)"));
static SEVERE_TOOL: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*(?:Error|Warning)-"));
static EXTENSION: LazyLock<Regex> = LazyLock::new(|| re(r"\.[A-Za-z][A-Za-z0-9]{0,5}$"));
static RNTST: LazyLock<Regex> =
    LazyLock::new(|| re(r"\[RNTST\]\s+Running test\s+([A-Za-z_][\w$]*)"));

/// Extensions of source files named outside quotes.
const SOURCE_EXT: &[&str] = &[
    "sv", "svh", "svi", "svp", "sva", "v", "vh", "vp", "vg", "vhd", "vhdl", "inc", "pkg",
];

fn is_source(path: &str) -> bool {
    path.rsplit_once('.')
        .is_some_and(|(_, ext)| SOURCE_EXT.iter().any(|e| e.eq_ignore_ascii_case(ext)))
}

/// The largest char boundary at or below `i`.
fn floor_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn overlaps(found: &[Link], start: usize, end: usize) -> bool {
    found.iter().any(|l| start < l.end && l.start < end)
}

fn add(out: &mut Vec<Link>, l: Link) {
    if l.end > l.start && !overlaps(out, l.start, l.end) {
        out.push(l);
    }
}

/// A UVM reporter that is a component path; a sequence on a sequencer is its sequencer.
fn component_of(reporter: &str) -> Option<&str> {
    let p = reporter.split("@@").next().unwrap_or(reporter);
    (p == "uvm_test_top" || p.starts_with("uvm_test_top.")).then_some(p)
}

fn delimits(c: u8) -> bool {
    c.is_ascii_whitespace() || b"\"'(),:;|<>=".contains(&c)
}

/// The path written just before `end` in `line` (outside quotes): back to a delimiter, with a
/// drive (`C:`) before it; `None` unless it names a source file.
fn path_before(line: &str, end: usize) -> Option<(usize, &str)> {
    let b = line.as_bytes();
    let mut s = end;
    while s > 0 && !delimits(b[s - 1]) {
        s -= 1;
    }
    if s >= 2
        && b[s - 1] == b':'
        && b[s - 2].is_ascii_alphabetic()
        && (s < 3 || delimits(b[s - 3]))
        && b.get(s).is_some_and(|c| *c == b'\\' || *c == b'/')
    {
        s -= 2;
    }
    let path = &line[s..end];
    is_source(path).then_some((s, path))
}

/// `line` without escape sequences, and for each byte offset of the result the offset in
/// `line` (one extra entry for the end).
fn strip_escapes(line: &str) -> (String, Option<Vec<usize>>) {
    if !line.contains('\x1b') {
        return (line.to_string(), None);
    }
    let mut map = Vec::with_capacity(line.len() + 1);
    let mut text = String::with_capacity(line.len());
    let mut last = 0;
    for m in ESCAPES.find_iter(line) {
        map.extend(last..m.start());
        text.push_str(&line[last..m.start()]);
        last = m.end();
    }
    map.extend(last..=line.len());
    text.push_str(&line[last..]);
    (text, Some(map))
}

fn mapped(map: Option<&Vec<usize>>, len: usize, i: usize) -> usize {
    map.map_or(i, |m| m.get(i).copied().unwrap_or(len))
}

fn number(s: &str) -> Option<u32> {
    s.parse().ok()
}

/// The links of one line (offsets in the line as written).
#[must_use]
pub fn line_links(raw: &str) -> Vec<Link> {
    let (full, map) = strip_escapes(raw);
    let line = &full[..floor_boundary(&full, MAX_LINE)];
    let mut out = Vec::new();
    for c in UVM.captures_iter(line) {
        if let (Some(file), Some(digits)) = (c.get(1), c.get(2))
            && let Some(n) = number(digits.as_str())
        {
            add(
                &mut out,
                Link {
                    start: file.start(),
                    end: digits.end() + 1,
                    target: Target::File {
                        path: file.as_str().to_string(),
                        line: n,
                    },
                },
            );
        }
        if let Some(rep) = c.get(3)
            && let Some(comp) = component_of(rep.as_str())
        {
            add(
                &mut out,
                Link {
                    start: rep.start(),
                    end: rep.start() + comp.len(),
                    target: Target::Component {
                        path: comp.to_string(),
                    },
                },
            );
        }
    }
    for c in QUOTED.captures_iter(line) {
        if let (Some(all), Some(path), Some(n)) = (c.get(0), c.get(1), c.get(2))
            && let Some(n) = number(n.as_str())
        {
            add(
                &mut out,
                Link {
                    start: all.start(),
                    end: all.end(),
                    target: Target::File {
                        path: path.as_str().to_string(),
                        line: n,
                    },
                },
            );
        }
    }
    for c in ANCHORS.captures_iter(line) {
        let Some(all) = c.get(0) else { continue };
        let n = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3));
        if let Some(n) = n.and_then(|n| number(n.as_str()))
            && let Some((start, path)) = path_before(line, all.start())
        {
            add(
                &mut out,
                Link {
                    start,
                    end: all.end(),
                    target: Target::File {
                        path: path.to_string(),
                        line: n,
                    },
                },
            );
        }
    }
    if let Some(c) = TASK_ONE_LINE.captures(line)
        && let (Some(path), Some(n)) = (c.get(1), c.get(2))
        && let Some(n) = number(n.as_str())
    {
        add(
            &mut out,
            Link {
                start: path.start(),
                end: path.end(),
                target: Target::File {
                    path: path.as_str().to_string(),
                    line: n,
                },
            },
        );
    }
    let len = raw.len();
    let mut out: Vec<Link> = out
        .into_iter()
        .map(|l| Link {
            start: mapped(map.as_ref(), len, l.start),
            end: mapped(map.as_ref(), len, l.end),
            ..l
        })
        .collect();
    out.sort_by_key(|l| l.start);
    out
}

/// The links of a whole log, in order, with the forms that span lines (a message's location
/// on the line after its header; an elaboration task's file and line on their own lines). At
/// most `max` links of ordinary lines and `max` more of errors and warnings, so a log full of
/// reports still has its failures linked.
#[must_use]
pub fn text_links(text: &str, max: usize) -> Vec<Link> {
    let mut links = Vec::new();
    // Links taken so far: [ordinary, severe].
    let mut taken = [0_usize; 2];
    let push = |l: Link, severe: bool, links: &mut Vec<Link>, taken: &mut [usize; 2]| {
        let n = &mut taken[usize::from(severe)];
        if *n < max {
            links.push(l);
            *n += 1;
        }
    };
    let (mut header, mut header_severe, mut task_file, mut last_severe) =
        (false, false, false, false);
    let mut task_path: Option<(usize, usize, String, bool)> = None;
    let mut pos = 0;
    while pos <= text.len() {
        let nl = text[pos..].find('\n').map_or(text.len(), |i| pos + i);
        let cut = floor_boundary(text, (pos + MAX_LINE * 4).min(nl));
        let raw = &text[pos..cut];
        let full = raw.strip_suffix('\r').unwrap_or(raw);
        let (plain, map) = strip_escapes(full);
        let severe = SEVERE.is_match(&plain) || (header && header_severe);
        let mut found = if MAYBE.is_match(&plain) {
            line_links(full)
        } else {
            Vec::new()
        };
        if header
            && found.is_empty()
            && let Some(c) = LOCATION.captures(&plain)
            && let (Some(path), Some(n)) = (c.get(1), c.get(2))
            && EXTENSION.is_match(path.as_str())
            && let Some(n) = number(n.as_str())
        {
            found.push(Link {
                start: mapped(map.as_ref(), full.len(), path.start()),
                end: mapped(map.as_ref(), full.len(), plain.trim_end().len()),
                target: Target::File {
                    path: path.as_str().to_string(),
                    line: n,
                },
            });
        }
        if let Some((start, end, path, sev)) = task_path.take() {
            if let Some(n) = TASK_LINE
                .captures(&plain)
                .and_then(|c| c.get(1))
                .and_then(|n| number(n.as_str()))
            {
                push(
                    Link {
                        start,
                        end,
                        target: Target::File { path, line: n },
                    },
                    sev,
                    &mut links,
                    &mut taken,
                );
            }
        } else if task_file && !plain.trim().is_empty() {
            let lead = full.len() - full.trim_start().len();
            task_path = Some((
                pos + lead,
                pos + full.trim_end().len(),
                plain.trim().to_string(),
                last_severe,
            ));
        }
        task_file = TASK_FILE.is_match(&plain);
        for l in found {
            push(
                Link {
                    start: l.start + pos,
                    end: l.end + pos,
                    ..l
                },
                severe,
                &mut links,
                &mut taken,
            );
        }
        if HEADER.is_match(&plain) {
            header = true;
            header_severe = SEVERE_HEADER.is_match(&plain);
        } else {
            header = header && plain.trim().is_empty();
        }
        if !plain.trim().is_empty() {
            last_severe = severe
                || SEVERE_TOOL.is_match(&plain)
                || (last_severe && plain.starts_with(char::is_whitespace));
        }
        if taken[0] >= max && taken[1] >= max {
            break;
        }
        pos = nl + 1;
    }
    links.sort_by_key(|l| l.start);
    links
}

/// The test a log ran (UVM's `[RNTST] Running test NAME...`); with `before`, the last one
/// starting at or before that offset (a log of several runs one after the other).
#[must_use]
pub fn log_test(text: &str, before: Option<usize>) -> Option<&str> {
    let mut found = None;
    for c in RNTST.captures_iter(text) {
        let (Some(all), Some(name)) = (c.get(0), c.get(1)) else {
            continue;
        };
        if before.is_some_and(|b| all.start() > b) {
            break;
        }
        found = Some(name.as_str());
    }
    found
}

/// A message's location on a line of its own (`rtl/top.sv, 42`), read without the header
/// before it: only a source file's path.
#[must_use]
pub fn location_line(line: &str) -> Option<Link> {
    let (plain, map) = strip_escapes(line);
    let c = LOCATION.captures(&plain)?;
    let (path, n) = (c.get(1)?, c.get(2)?);
    if !is_source(path.as_str()) {
        return None;
    }
    Some(Link {
        start: mapped(map.as_ref(), line.len(), path.start()),
        end: mapped(map.as_ref(), line.len(), plain.trim_end().len()),
        target: Target::File {
            path: path.as_str().to_string(),
            line: number(n.as_str())?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, line: u32) -> Target {
        Target::File {
            path: path.to_string(),
            line,
        }
    }

    fn targets(links: &[Link]) -> Vec<Target> {
        links.iter().map(|l| l.target.clone()).collect()
    }

    #[test]
    fn uvm_report_with_file_and_component() {
        let l =
            "UVM_ERROR ../tb/alpha sb.sv(142) @ 1500: uvm_test_top.env.sb [AB_CD] value differs";
        let links = line_links(l);
        assert_eq!(
            targets(&links),
            vec![
                file("../tb/alpha sb.sv", 142),
                Target::Component {
                    path: "uvm_test_top.env.sb".to_string()
                }
            ]
        );
        assert_eq!(&l[links[0].start..links[0].end], "../tb/alpha sb.sv(142)");
        // A sequence on a sequencer links to the sequencer; reporters outside the test are none.
        let l = "UVM_INFO(UVM_LOW) @ 0: uvm_test_top.env.sqr@@seq [X] started";
        assert_eq!(
            targets(&line_links(l)),
            vec![Target::Component {
                path: "uvm_test_top.env.sqr".to_string()
            }]
        );
        assert_eq!(line_links("UVM_INFO @ 0: reporter [Y] hello"), Vec::new());
    }

    #[test]
    fn quoted_anchor_and_drive_forms() {
        assert_eq!(
            targets(&line_links(r#"Error: "a/b.svh", 7: top.u: at time 5 ns"#)),
            vec![file("a/b.svh", 7)]
        );
        assert_eq!(
            targets(&line_links("see C:/w/x.sv(3) and y.v:9:2 and z.sv,4|1")),
            vec![file("C:/w/x.sv", 3), file("y.v", 9), file("z.sv", 4)]
        );
        // Not a source file: no link.
        assert_eq!(line_links("version 2.0:15 and notes.txt(4)"), Vec::new());
        assert_eq!(
            targets(&line_links("  location: file rtl/q.sv line 12")),
            vec![file("rtl/q.sv", 12)]
        );
    }

    #[test]
    fn escapes_are_skipped_and_offsets_kept() {
        let l = "\x1b[31mUVM_ERROR k.sv(2) @ 1: uvm_test_top [I] m\x1b[0m";
        let links = line_links(l);
        assert_eq!(&l[links[0].start..links[0].end], "k.sv(2)");
    }

    #[test]
    fn multi_line_forms_and_budgets() {
        let text = "Error-[ABC] something wrong\n  rtl/top.sv, 42\nplain line\nlocation: file\n  tb/t.sv\n  line 8\n";
        let links = text_links(text, 10);
        assert_eq!(
            targets(&links),
            vec![file("rtl/top.sv", 42), file("tb/t.sv", 8)]
        );
        assert_eq!(&text[links[0].start..links[0].end], "rtl/top.sv, 42");
        // Ordinary links are capped; error links have their own budget.
        let many = "x.sv(1)\nx.sv(2)\nx.sv(3)\nUVM_ERROR e.sv(9) @ 0: r [Q] m\n";
        assert_eq!(
            targets(&text_links(many, 2)),
            vec![file("x.sv", 1), file("x.sv", 2), file("e.sv", 9)]
        );
    }

    #[test]
    fn test_name_and_location_line() {
        let t = "a\nUVM_INFO @ 0: reporter [RNTST] Running test first_t...\nUVM_INFO @ 0: reporter [RNTST] Running test second_t...\n";
        assert_eq!(log_test(t, None), Some("second_t"));
        assert_eq!(log_test(t, Some(60)), Some("first_t"));
        assert_eq!(log_test(t, Some(10)), None);
        assert_eq!(
            location_line("  rtl/top.sv, 42 ").map(|l| l.target),
            Some(file("rtl/top.sv", 42))
        );
        assert!(location_line("version 1, 2").is_none());
    }

    #[test]
    fn long_and_multibyte_lines_do_not_panic() {
        let long = format!("{}é x.sv(1)", "é".repeat(MAX_LINE));
        let _ = line_links(&long);
        let _ = text_links(&long, 5);
        assert_eq!(targets(&line_links("é x.sv(1)")), vec![file("x.sv", 1)]);
    }
}
