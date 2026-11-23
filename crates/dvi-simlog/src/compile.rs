//! What a simulator compiled, read from its log (ported from DVICode's `simlog.rs`):
//!
//! - VCS and vlogan: the `Parsing design|library|included file '...'` messages, and the
//!   defines and include directories of the command line the log shows (`Command: ...`,
//!   `Command  = ...`, or a line starting with the tool).
//! - Questa: the `vlog ...` command lines (`# vlog ...` in a transcript), read like an
//!   argument file (Questa does not list the files it parses).

use std::collections::HashSet;

/// The compile of one log, as written there (paths not resolved).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompileLog {
    /// Files compiled, in order.
    pub files: Vec<String>,
    /// Library (`-y`/`-v`) files the compile used.
    pub lib_files: Vec<String>,
    /// Files included by `` `include ``.
    pub included: Vec<String>,
    /// `NAME` or `NAME=VALUE`, from the command line.
    pub defines: Vec<String>,
    /// `+incdir+` directories of the command line.
    pub incdirs: Vec<String>,
    /// A command line was found.
    pub command: bool,
    /// The compiler of the command line (`vcs`, `vlogan`, `vlog`...), without path or `.exe`.
    pub tool: String,
    /// The words of the command line after the tool.
    pub words: Vec<String>,
}

impl CompileLog {
    /// A Questa compile: its files are the words of its command line.
    #[must_use]
    pub fn from_command_line(&self) -> bool {
        matches!(self.tool.as_str(), "vlog" | "qverilog")
    }
}

/// The compiler a word names: `/tools/x/bin/vcs`, `C:\q\win64\vlog.exe`.
fn tool_name(w: &str) -> Option<&'static str> {
    let w = w.trim_matches('"');
    let name = w.rsplit(['/', '\\']).next().unwrap_or(w);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    ["vcs", "vlogan", "vhdlan", "vlog", "qverilog"]
        .into_iter()
        .find(|t| *t == name)
}

/// The quoted path of a `Parsing <kind> file '<path>'` message.
fn parsed_file<'a>(line: &'a str, kind: &str) -> Option<&'a str> {
    let rest = line
        .strip_prefix("Parsing ")?
        .strip_prefix(kind)?
        .strip_prefix(" file ")?;
    let rest = rest.strip_prefix('\'').or_else(|| rest.strip_prefix('"'))?;
    let end = rest.find(['\'', '"'])?;
    Some(&rest[..end]).filter(|p| !p.is_empty())
}

/// Whether a `'` after `prev`, followed by `next` and `after`, is an unsized literal given as
/// a value (`='0`, `='1`, `='x`, `='z` not followed by a name) rather than an opening quote.
fn unsized_literal(prev: Option<char>, next: Option<char>, after: Option<char>) -> bool {
    prev == Some('=')
        && next.is_some_and(|c| matches!(c, '0' | '1' | 'x' | 'X' | 'z' | 'Z'))
        && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Whether the `'` at `b[i]` starts quoted text rather than a number such as `8'hFF` or
/// `'hFF`: not right after a letter or digit, and closed later on the same line.
fn opens_quote(b: &[u8], i: usize) -> bool {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return false;
    }
    let ch = |j: Option<usize>| j.and_then(|j| b.get(j)).map(|c| char::from(*c));
    if unsized_literal(ch(i.checked_sub(1)), ch(Some(i + 1)), ch(Some(i + 2))) {
        return false;
    }
    b[i + 1..]
        .iter()
        .take_while(|c| **c != b'\n')
        .any(|c| *c == b'\'')
}

/// Splits `A=1+B+C="x+y"` into defines; a `+` starts a new define only when followed by an
/// identifier and not inside quotes.
fn split_defines(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let quote_start = c == '"'
            || (c == '\''
                && !(i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_'))
                && !unsized_literal(
                    i.checked_sub(1).map(|p| chars[p]),
                    chars.get(i + 1).copied(),
                    chars.get(i + 2).copied(),
                )
                && chars[i + 1..].contains(&'\''));
        match quote {
            Some('"') if c == '\\' && i + 1 < chars.len() => {
                cur.push(c);
                cur.push(chars[i + 1]);
                i += 2;
                continue;
            }
            Some(q) if c == q => quote = None,
            None if quote_start => quote = Some(c),
            None if c == '+' => {
                let next_ident = chars
                    .get(i + 1)
                    .is_some_and(|n| n.is_ascii_alphabetic() || *n == '_');
                if next_ident || cur.is_empty() {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                    i += 1;
                    continue;
                }
            }
            _ => {}
        }
        cur.push(c);
        i += 1;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The words of a command line; quotes keep spaces in a word and stay in it; a backslash
/// keeps the next character. An apostrophe in a number (`8'hff`) is not a quote.
fn shell_words(line: &str) -> Vec<String> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.char_indices();
    while let Some((i, c)) = chars.next() {
        match (quote, c) {
            (_, '\\') => {
                cur.push(c);
                if let Some((_, n)) = chars.next() {
                    cur.push(n);
                }
            }
            (None, '"') => {
                quote = Some(c);
                cur.push(c);
            }
            (None, '\'') if opens_quote(b, i) => {
                quote = Some(c);
                cur.push(c);
            }
            (Some(q), _) if c == q => {
                quote = None;
                cur.push(c);
            }
            (None, _) if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The parts of `a+"b+c"+d` (`a`, `b+c`, `d`): split at `+` outside quotes, quotes removed.
fn split_plus(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if c == q => quote = None,
            (None, '+') => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.retain(|p| !p.is_empty());
    out
}

/// The command line of a log line, as words: `Command: ...`, `Command  = wrapper tool ...`,
/// `Command arguments: ...`, or a line whose first word is the tool.
fn command_words(line: &str) -> Option<Vec<String>> {
    let tool = |w: &str| tool_name(w).is_some();
    let words = shell_words(line);
    let start = if line.trim_start().starts_with("Command") {
        let sep = words
            .iter()
            .position(|w| w.ends_with(':') || w.ends_with('='))?;
        sep + 1
    } else if words.first().is_some_and(|w| tool(w)) {
        0
    } else {
        return None;
    };
    let words = &words[start..];
    let has_tool = words.iter().take(4).any(|w| tool(w));
    let has_opts = words
        .iter()
        .any(|w| w.starts_with("+define+") || w.starts_with("+incdir+"));
    (has_tool || has_opts).then(|| words.to_vec())
}

/// Values in order, each once.
#[derive(Default)]
struct Ordered {
    v: Vec<String>,
    seen: HashSet<String>,
}

impl Ordered {
    fn push(&mut self, x: &str) {
        if self.seen.insert(x.to_string()) {
            self.v.push(x.to_string());
        }
    }
}

/// The compiles of a log, one per compile command, each with the files parsed after its
/// command line and the defines and include directories of that command. Files parsed
/// before any command line belong to the first.
#[must_use]
pub fn parse_compiles(text: &str) -> Vec<CompileLog> {
    let mut runs = Vec::new();
    let mut run = Run::default();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let line = line.strip_prefix("# ").unwrap_or(line);
        // The same command twice in a row (echoed as typed, then printed with its options
        // quoted) is one compile.
        if run.command
            && run.files.v.is_empty()
            && let Some(words) = command_words(line)
        {
            let plain = |ws: &[String]| {
                ws.iter()
                    .map(|w| w.trim_matches('"').to_string())
                    .collect::<Vec<_>>()
            };
            let at = words
                .iter()
                .position(|w| tool_name(w).is_some())
                .map_or(0, |i| i + 1);
            if plain(&words[at..]) == plain(&run.words) {
                continue;
            }
        }
        if command_words(line).is_some() && run.command {
            runs.push(std::mem::take(&mut run).finish());
        }
        run.line(line, &mut lines);
    }
    runs.push(run.finish());
    runs
}

#[derive(Default)]
struct Run {
    files: Ordered,
    lib_files: Ordered,
    included: Ordered,
    defines: Ordered,
    incdirs: Ordered,
    command: bool,
    tool: String,
    words: Vec<String>,
}

impl Run {
    fn finish(self) -> CompileLog {
        CompileLog {
            files: self.files.v,
            lib_files: self.lib_files.v,
            included: self.included.v,
            defines: self.defines.v,
            incdirs: self.incdirs.v,
            command: self.command,
            tool: self.tool,
            words: self.words,
        }
    }

    fn line<'a>(&mut self, line: &str, lines: &mut impl Iterator<Item = &'a str>) {
        if let Some(p) = parsed_file(line, "design") {
            self.files.push(p);
        } else if let Some(p) = parsed_file(line, "library") {
            self.lib_files.push(p);
        } else if let Some(p) = parsed_file(line, "included") {
            self.included.push(p);
        } else if command_words(line).is_some() {
            // The whole command: a line ending in `\` goes on with the next one.
            let mut logical = line.to_string();
            while logical.ends_with('\\') {
                logical.pop();
                let Some(next) = lines.next() else { break };
                logical.push_str(next.trim_end());
            }
            let words = command_words(&logical).unwrap_or_default();
            self.command = true;
            if let Some(at) = words.iter().position(|w| tool_name(w).is_some()) {
                self.tool = tool_name(&words[at]).unwrap_or_default().to_string();
                self.words = words[at + 1..].to_vec();
            }
            let mut i = 0;
            while i < words.len() {
                let w = words[i].as_str();
                if let Some(rest) = w.strip_prefix("+define+") {
                    for d in split_defines(rest) {
                        self.defines.push(&d);
                    }
                } else if let Some(rest) = w.strip_prefix("+incdir+") {
                    for d in split_plus(rest) {
                        self.incdirs.push(&d);
                    }
                } else if (w == "-define" || w == "-D") && i + 1 < words.len() {
                    i += 1;
                    self.defines.push(&words[i]);
                } else if w == "-incdir" && i + 1 < words.len() {
                    i += 1;
                    self.incdirs.push(&split_plus(&words[i]).concat());
                }
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(text: &str) -> CompileLog {
        parse_compiles(text).into_iter().next().unwrap_or_default()
    }

    // Invented logs: only the message forms the parser reads, with made-up names.
    #[test]
    fn reads_parsed_files_and_command_options() {
        let log = "\
Command  = wrap vcs -full64 +define+FEAT_OFF +define+A=1+B -define C +incdir+inc+../other -f list.f
some banner text
Parsing design file '/lib/pkg_a.sv'
Parsing included file '/lib/macros_a.svh'.
Parsing design file 'rtl/core.sv'
Parsing design file '/lib/pkg_a.sv'
Parsing library file '/cells/and2.v'
";
        let s = first(log);
        assert_eq!(s.files, vec!["/lib/pkg_a.sv", "rtl/core.sv"]);
        assert_eq!(s.lib_files, vec!["/cells/and2.v"]);
        assert_eq!(s.included, vec!["/lib/macros_a.svh"]);
        assert_eq!(s.defines, vec!["FEAT_OFF", "A=1", "B", "C"]);
        assert_eq!(s.incdirs, vec!["inc", "../other"]);
        assert_eq!(s.tool, "vcs");
        assert!(s.command);
    }

    #[test]
    fn prose_is_not_a_command_and_questa_lines_are() {
        let s = first(
            "vlogan -sverilog +define+X +incdir+a\nThe tool vcs was not used\nParsing design file \"b.sv\"\n",
        );
        assert_eq!(
            (s.defines, s.incdirs, s.files),
            (
                vec!["X".to_string()],
                vec!["a".to_string()],
                vec!["b.sv".to_string()]
            )
        );
        assert_eq!(
            first("Please rerun vcs with more options\n").defines,
            Vec::<String>::new()
        );
        let s = first("# vlog -sv +define+Q top.sv\n# vlog -sv \"+define+Q\" top.sv\n");
        assert!(s.from_command_line());
        assert_eq!(
            parse_compiles("# vlog -sv +define+Q top.sv\n# vlog -sv \"+define+Q\" top.sv\n").len(),
            1
        );
    }

    #[test]
    fn one_compile_per_command() {
        let log = "Parsing design file 'early.sv'\nCommand: vlogan +define+A a.sv\nParsing design file 'a.sv'\nCommand: vlogan +define+B b.sv\nParsing design file 'a.sv'\nParsing design file 'b.sv'\nCommand: vcs top -o out\n";
        let got: Vec<(Vec<String>, Vec<String>)> = parse_compiles(log)
            .iter()
            .map(|r| (r.files.clone(), r.defines.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    vec!["early.sv".to_string(), "a.sv".to_string()],
                    vec!["A".to_string()]
                ),
                (
                    vec!["a.sv".to_string(), "b.sv".to_string()],
                    vec!["B".to_string()]
                ),
                (vec![], vec![]),
            ]
        );
    }

    #[test]
    fn quoted_values_and_continued_lines() {
        let s = first(
            "Command: vcs +incdir+\"include dir\" +define+MSG=\"hello world\" \\\n   -incdir 'other dir' +define+B\nParsing design file 'a.sv'\n",
        );
        assert_eq!(s.incdirs, vec!["include dir", "other dir"]);
        assert_eq!(s.defines, vec!["MSG=\"hello world\"", "B"]);
        let s = first(
            "Command: vcs +incdir+inc\\\n/headers +define+WIDTH=8'hff +incdir+\"a+b\" +define+ONES='1+B\n",
        );
        assert_eq!(s.incdirs, vec!["inc/headers", "a+b"]);
        assert_eq!(s.defines, vec!["WIDTH=8'hff", "ONES='1", "B"]);
    }
}
