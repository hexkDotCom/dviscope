//! Streaming decode: bytes → lines with byte offsets. Line breaks are LF,
//! CRLF and CR; a line longer than [`MAX_LINE_BYTES`] keeps its first bytes (cut on a UTF-8
//! character boundary) and the rest is drained without buffering. Invalid UTF-8 in the kept
//! text is replaced and counted.

use dviscope_model::limits::MAX_LINE_BYTES;

/// One decoded line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// 1-based line number.
    pub no: u64,
    /// First byte (0-based, inclusive).
    pub start: u64,
    /// End byte (exclusive), before the line break.
    pub end: u64,
    /// Decoded text (possibly cut).
    pub text: String,
    /// The line was longer than the limit.
    pub cut: bool,
}

/// Counts of line breaks seen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Endings {
    /// `\n`.
    pub lf: u64,
    /// `\r\n`.
    pub crlf: u64,
    /// lone `\r`.
    pub cr: u64,
}

/// Splits a byte stream into lines, independent of how the stream is chunked.
#[derive(Debug, Default)]
pub struct Splitter {
    buf: Vec<u8>,
    line_start: u64,
    line_len: u64,
    cut: bool,
    pending_cr: bool,
    offset: u64,
    next_no: u64,
    /// Line breaks seen.
    pub endings: Endings,
    /// Invalid UTF-8 bytes replaced in kept text.
    pub invalid_bytes: u64,
}

impl Splitter {
    /// A new splitter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_no: 1,
            ..Self::default()
        }
    }

    fn take_line(&mut self, out: &mut dyn FnMut(Line)) {
        let keep = cut_point(&self.buf, self.cut);
        let (text, invalid) = decode(&self.buf[..keep]);
        self.invalid_bytes += invalid;
        out(Line {
            no: self.next_no,
            start: self.line_start,
            end: self.line_start + self.line_len,
            text,
            cut: self.cut,
        });
        self.next_no += 1;
        self.buf.clear();
        self.line_len = 0;
        self.cut = false;
    }

    /// Feeds bytes; each complete line is handed to `out` as soon as it is cut.
    pub fn push(&mut self, mut bytes: &[u8], out: &mut dyn FnMut(Line)) {
        while !bytes.is_empty() {
            if self.pending_cr {
                self.pending_cr = false;
                if bytes[0] == b'\n' {
                    self.endings.crlf += 1;
                    bytes = &bytes[1..];
                    self.offset += 1;
                    self.line_start = self.offset;
                    continue;
                }
                self.endings.cr += 1;
            }
            match bytes.iter().position(|&b| b == b'\n' || b == b'\r') {
                None => {
                    self.append(bytes);
                    self.offset += bytes.len() as u64;
                    return;
                }
                Some(i) => {
                    self.append(&bytes[..i]);
                    self.offset += i as u64;
                    self.take_line(out);
                    self.offset += 1;
                    if bytes[i] == b'\n' {
                        self.endings.lf += 1;
                    } else {
                        self.pending_cr = true;
                    }
                    self.line_start = self.offset;
                    bytes = &bytes[i + 1..];
                }
            }
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.line_len += bytes.len() as u64;
        // Keep up to the limit plus a few bytes so a cut can end on a character boundary.
        let room = (MAX_LINE_BYTES + 3).saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        if self.line_len > MAX_LINE_BYTES as u64 {
            self.cut = true;
        }
    }

    /// Ends the stream: a last line without a line break is emitted if it has bytes.
    pub fn finish(&mut self, out: &mut dyn FnMut(Line)) {
        if self.pending_cr {
            self.pending_cr = false;
            self.endings.cr += 1;
        }
        if self.line_len > 0 {
            self.take_line(out);
        }
    }

    /// A stream boundary (the next bytes come from another file): the current line ends here
    /// even without a line break, and a pending `\r` counts as a lone one (a `\n` after the
    /// boundary starts a new line). Line numbers and byte offsets continue.
    pub fn boundary(&mut self, out: &mut dyn FnMut(Line)) {
        self.finish(out);
        self.line_start = self.offset;
    }

    /// Total bytes seen.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.offset
    }
}

/// Where to cut a long line: at most `MAX_LINE_BYTES`, on a character boundary.
fn cut_point(buf: &[u8], cut: bool) -> usize {
    if !cut || buf.len() <= MAX_LINE_BYTES {
        return buf.len();
    }
    let mut i = MAX_LINE_BYTES;
    // Back off over continuation bytes (at most 3) to the start of a character.
    let mut steps = 0;
    while i > 0 && steps < 3 && (buf[i] & 0xC0) == 0x80 {
        i -= 1;
        steps += 1;
    }
    i
}

/// Decodes UTF-8, replacing invalid sequences with U+FFFD and counting the invalid bytes.
#[must_use]
pub fn decode(mut bytes: &[u8]) -> (String, u64) {
    let mut out = String::with_capacity(bytes.len());
    let mut invalid = 0u64;
    loop {
        match std::str::from_utf8(bytes) {
            Ok(s) => {
                out.push_str(s);
                return (out, invalid);
            }
            Err(e) => {
                let good = e.valid_up_to();
                out.push_str(std::str::from_utf8(&bytes[..good]).unwrap_or_default());
                out.push('\u{FFFD}');
                let bad = e.error_len().unwrap_or(bytes.len() - good);
                invalid += bad as u64;
                bytes = &bytes[good + bad..];
            }
        }
    }
}

/// Truncates text to at most `max` bytes on a character boundary.
#[must_use]
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_all(chunks: &[&[u8]]) -> (Vec<Line>, Endings, u64) {
        let mut s = Splitter::new();
        let mut out = vec![];
        for c in chunks {
            s.push(c, &mut |l| out.push(l));
        }
        s.finish(&mut |l| out.push(l));
        (out, s.endings, s.invalid_bytes)
    }

    #[test]
    fn line_breaks_and_offsets() {
        let (lines, e, _) = split_all(&[b"a\r\nbb\rc\n\nd"]);
        let got: Vec<_> = lines
            .iter()
            .map(|l| (l.text.as_str(), l.start, l.end))
            .collect();
        assert_eq!(
            got,
            [
                ("a", 0, 1),
                ("bb", 3, 5),
                ("c", 6, 7),
                ("", 8, 8),
                ("d", 9, 10)
            ]
        );
        assert_eq!((e.lf, e.crlf, e.cr), (2, 1, 1));
    }

    #[test]
    fn crlf_split_across_chunks() {
        let (a, ea, _) = split_all(&[b"x\r", b"\ny\r", b"z"]);
        let (b, eb, _) = split_all(&[b"x\r\ny\rz"]);
        assert_eq!(a, b);
        assert_eq!(ea, eb);
    }

    #[test]
    fn invalid_utf8_is_counted() {
        let (lines, _, invalid) = split_all(&[b"ok \xff\xfe end\n\xe2\x82", b"\xac\n"]);
        assert_eq!(lines[0].text, "ok \u{FFFD}\u{FFFD} end");
        assert_eq!(lines[1].text, "\u{20AC}");
        assert_eq!(invalid, 2);
    }

    #[test]
    fn long_line_is_cut_on_a_character_boundary() {
        let mut long = vec![b'a'; MAX_LINE_BYTES - 1];
        long.extend_from_slice("\u{20AC}".as_bytes());
        long.extend_from_slice(&[b'b'; 1000]);
        long.push(b'\n');
        let (lines, _, invalid) = split_all(&[&long, b"next"]);
        assert!(lines[0].cut);
        assert_eq!(lines[0].text.len(), MAX_LINE_BYTES - 1);
        assert_eq!(
            lines[0].end - lines[0].start,
            (MAX_LINE_BYTES + 2 + 1000) as u64
        );
        assert_eq!(lines[1].text, "next");
        assert_eq!(invalid, 0);
    }
}
