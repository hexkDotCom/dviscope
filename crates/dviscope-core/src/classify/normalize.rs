//! Normalizers: pure and idempotent; they never touch `diag_id`/`checker_id`.
//! Normalization is not redaction.
//!
//! | Name | Replaces | With |
//! |---|---|---|
//! | `sv_literal` | `8'hff`, `'b10x1`, `4'sd3`; unbased `'0` `'1` `'x` `'z` | `<SV:h>`, `<SV:bx>`; `<SV:u>`, `<SV:ux>` (radix kept; `x` when X/Z digits) |
//! | `hex` | `0x1f`; words of ≥ 6 hex digits with a decimal digit; a value of ≥ 4 hex digits after `=` | `<HEX>` |
//! | `time` | `12.5 ns`, `30ps` | `<T>` |
//! | `path` | absolute Windows, WSL and POSIX paths (incl. `user@HOST` temp folders) | `<P>/basename` |
//! | `number` | decimal integers | `<N>` |
//! | `whitespace` | runs of white space | one space, trimmed |
//! | `suffix_strip` | every trailing parenthesized group | nothing |
//! | `index_fold` (opt-in) | `[12]`, `name_12` | `[*]`, `name_*` |

use std::sync::OnceLock;

use dviscope_model::wire::evidence::Normalization;
use regex::{Captures, Regex};

/// Maximum normalization records kept per event.
pub const MAX_RECORDS: usize = 16;

struct Res {
    sv: Regex,
    hex0x: Regex,
    hexbare: Regex,
    hexvalue: Regex,
    suffix_index: Regex,
    time: Regex,
    winpath: Regex,
    posixpath: Regex,
    number: Regex,
    ws: Regex,
    suffix: Regex,
    unbased: Regex,
    index: Regex,
}

fn res() -> Option<&'static Res> {
    static R: OnceLock<Option<Res>> = OnceLock::new();
    R.get_or_init(|| {
        Some(Res {
            sv: Regex::new(r"(?:\b\d+)?'[sS]?([bBoOdDhH])([0-9a-fA-FxXzZ_?]+)").ok()?,
            hex0x: Regex::new(r"\b0[xX][0-9a-fA-F]+\b").ok()?,
            hexbare: Regex::new(r"\b[0-9a-fA-F]{6,}\b").ok()?,
            hexvalue: Regex::new(r"=([0-9a-fA-F]{4,})\b").ok()?,
            suffix_index: Regex::new(r"([A-Za-z])_\d+\b").ok()?,
            time: Regex::new(r"\b\d+(?:\.\d+)?\s?(?:fs|ps|ns|us|ms|s)\b").ok()?,
            winpath: Regex::new(r#"\b[A-Za-z]:[\\/][^\s"'()<>,;]*"#).ok()?,
            posixpath: Regex::new(r#"(?:^|[\s"'(=])(/[^\s"'()<>,;/]+(?:/[^\s"'()<>,;/]*)+)"#)
                .ok()?,
            number: Regex::new(r"\b\d+\b").ok()?,
            ws: Regex::new(r"\s+").ok()?,
            suffix: Regex::new(r"(?:\s*\([^()]*\))+\s*$").ok()?,
            unbased: Regex::new(r"'([01xXzZ])\b").ok()?,
            index: Regex::new(r"\[\d+\]").ok()?,
        })
    })
    .as_ref()
}

fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

fn record(out: &mut Vec<Normalization>, name: &str, original: &str, replacement: &str) {
    if out.len() < MAX_RECORDS && original != replacement {
        out.push(Normalization {
            normalizer: name.to_string(),
            original: original.to_string(),
            replacement: replacement.to_string(),
        });
    }
}

/// Whether a normalizer can change the text at all (a cheap byte test before its regexes).
fn may_apply(name: &str, text: &str) -> bool {
    let b = text.as_bytes();
    let digit = || b.iter().any(u8::is_ascii_digit);
    match name {
        "sv_literal" => b.contains(&b'\''),
        "hex" => b.iter().any(u8::is_ascii_hexdigit),
        "time" | "number" | "index_fold" => digit(),
        "path" => b.iter().any(|&c| c == b'/' || c == b'\\'),
        "whitespace" => {
            b.first().is_some_and(u8::is_ascii_whitespace)
                || b.last().is_some_and(u8::is_ascii_whitespace)
                || b.windows(2).any(|w| {
                    w[0].is_ascii_whitespace() && (w[1].is_ascii_whitespace() || w[0] != b' ')
                })
        }
        "suffix_strip" => b.contains(&b')'),
        _ => true,
    }
}

/// Applies one normalizer.
#[must_use]
pub fn apply_one(name: &str, text: &str, log: &mut Vec<Normalization>) -> String {
    let Some(r) = res() else {
        return text.to_string();
    };
    if !may_apply(name, text) {
        return text.to_string();
    }
    match name {
        "sv_literal" => {
            let t = r.sv.replace_all(text, |c: &Captures<'_>| {
                let radix = c[1].to_ascii_lowercase();
                let x = c[2]
                    .bytes()
                    .any(|b| matches!(b, b'x' | b'X' | b'z' | b'Z' | b'?'));
                let rep = format!("<SV:{radix}{}>", if x { "x" } else { "" });
                record(log, name, &c[0], &rep);
                rep
            });
            r.unbased
                .replace_all(&t, |c: &Captures<'_>| {
                    let rep = if matches!(&c[1], "x" | "X" | "z" | "Z") {
                        "<SV:ux>"
                    } else {
                        "<SV:u>"
                    };
                    record(log, name, &c[0], rep);
                    rep.to_string()
                })
                .into_owned()
        }
        "hex" => {
            let t = r.hex0x.replace_all(text, |c: &Captures<'_>| {
                record(log, name, &c[0], "<HEX>");
                "<HEX>".to_string()
            });
            let t = r.hexvalue.replace_all(&t, |c: &Captures<'_>| {
                record(log, name, &c[1], "<HEX>");
                "=<HEX>".to_string()
            });
            r.hexbare
                .replace_all(&t, |c: &Captures<'_>| {
                    let w = &c[0];
                    // A data word: six or more hex digits, at least one a decimal digit
                    // (all-decimal words of that length are data too: %h prints them).
                    if w.bytes().any(|b| b.is_ascii_digit()) {
                        record(log, name, w, "<HEX>");
                        "<HEX>".to_string()
                    } else {
                        w.to_string()
                    }
                })
                .into_owned()
        }
        "time" => r
            .time
            .replace_all(text, |c: &Captures<'_>| {
                record(log, name, &c[0], "<T>");
                "<T>".to_string()
            })
            .into_owned(),
        "path" => {
            let t = r.winpath.replace_all(text, |c: &Captures<'_>| {
                let rep = format!("<P>/{}", basename(&c[0]));
                record(log, name, &c[0], &rep);
                rep
            });
            r.posixpath
                .replace_all(&t, |c: &Captures<'_>| {
                    let whole = &c[0];
                    let path = &c[1];
                    let lead = &whole[..whole.len() - path.len()];
                    let rep = format!("<P>/{}", basename(path));
                    record(log, name, path, &rep);
                    format!("{lead}{rep}")
                })
                .into_owned()
        }
        "number" => r
            .number
            .replace_all(text, |c: &Captures<'_>| {
                record(log, name, &c[0], "<N>");
                "<N>".to_string()
            })
            .into_owned(),
        "whitespace" => r.ws.replace_all(text, " ").trim().to_string(),
        "suffix_strip" => r.suffix.replace(text, "").into_owned(),
        "index_fold" => {
            let t = r.index.replace_all(text, |c: &Captures<'_>| {
                record(log, name, &c[0], "[*]");
                "[*]".to_string()
            });
            r.suffix_index
                .replace_all(&t, |c: &Captures<'_>| {
                    let rep = format!("{}_*", &c[1]);
                    record(log, name, &c[0], &rep);
                    rep
                })
                .into_owned()
        }
        _ => text.to_string(),
    }
}

/// Applies normalizers in order.
#[must_use]
pub fn apply(names: &[String], text: &str, log: &mut Vec<Normalization>) -> String {
    names
        .iter()
        .fold(text.to_string(), |t, n| apply_one(n, &t, log))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn all() -> Vec<String> {
        ["sv_literal", "hex", "time", "path", "number", "whitespace"]
            .map(String::from)
            .to_vec()
    }

    fn norm(t: &str) -> String {
        apply(&all(), t, &mut vec![])
    }

    #[test]
    fn examples() {
        assert_eq!(
            norm("lhs = 'h74c5cefd : rhs = 4'b10x1"),
            "lhs = <SV:h> : rhs = <SV:bx>"
        );
        assert_eq!(norm("act=0x0 exp=0xa"), "act=<HEX> exp=<HEX>");
        assert_eq!(
            norm("glitch at 2005000 data=9960a374"),
            "glitch at <HEX> data=<HEX>"
        );
        assert_eq!(norm("data=12345678 n=42"), "data=<HEX> n=<N>");
        assert_eq!(norm("at 12.5 ns and 30ps"), "at <T> and <T>");
        assert_eq!(
            norm(r"see D:/w/user@HOST_dpi_1/x/a.sv and C:\t\b.dll"),
            "see <P>/a.sv and <P>/b.dll"
        );
        assert_eq!(
            norm("file \"/home/u/.cache/w/x.sv\", 46"),
            "file \"<P>/x.sv\", <N>"
        );
        assert_eq!(norm("  a \t b  "), "a b");
        assert_eq!(
            apply_one("index_fold", "env.agent[3].mon", &mut vec![]),
            "env.agent[*].mon"
        );
        assert_eq!(
            apply_one("index_fold", "regs.mem_17: x_1", &mut vec![]),
            "regs.mem_*: x_*"
        );
        assert_eq!(norm("regs.mem_17: read 'h1"), "regs.mem_17: read <SV:h>");
        assert_eq!(norm("data=cdefaefb mode=on"), "data=<HEX> mode=on");
        assert_eq!(
            apply_one("suffix_strip", "value differs (7 times)", &mut vec![]),
            "value differs"
        );
        assert_eq!(
            apply_one("suffix_strip", "value (a) (b)", &mut vec![]),
            "value"
        );
        assert_eq!(
            norm("act='0 exp='1 v='x"),
            "act=<SV:u> exp=<SV:u> v=<SV:ux>"
        );
        assert_eq!(norm("deadbeef added facade"), "deadbeef added facade");
    }

    #[test]
    fn records_are_bounded() {
        let mut log = vec![];
        let _ = apply(&all(), &"1 ".repeat(100), &mut log);
        assert_eq!(log.len(), MAX_RECORDS);
    }

    proptest! {
        #[test]
        fn idempotent(s in "[ -~]{0,80}") {
            let once = norm(&s);
            prop_assert_eq!(norm(&once), once.clone());
        }

        #[test]
        fn every_normalizer_is_idempotent_alone(s in "[ -~]{0,60}") {
            for n in crate::packs::NORMALIZERS {
                let once = apply_one(n, &s, &mut vec![]);
                prop_assert_eq!(apply_one(n, &once, &mut vec![]), once.clone(), "{}", n);
            }
        }

        #[test]
        fn idempotent_on_log_like_text(
            a in "[a-z_]{1,8}", n in 0u32..100_000, h in "[0-9a-f]{8}", t in 0u32..9999,
        ) {
            let s = format!("{a} {n} data=0x{h} at {t}.000ns '{h} /x/{a}/y.sv");
            let once = norm(&s);
            prop_assert_eq!(norm(&once), once.clone());
        }
    }
}
