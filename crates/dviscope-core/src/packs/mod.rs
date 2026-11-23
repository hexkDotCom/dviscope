//! Pattern packs: parsing, validation and compilation into an immutable
//! [`Pipeline`] keyed by its digest. The grammar reference is `docs/packs.md`.

pub mod schema;
pub mod shipped;

use std::collections::{BTreeMap, BTreeSet};

use dviscope_model::canonical::{Digest, digest_of};
use dviscope_model::wire::evidence::VerdictSourceKind as K;
use dviscope_model::wire::evidence::{CounterDomain, CounterRole, DiagKind, Framework, Phase};
use dviscope_model::wire::manifest::Severity;
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde_json::json;

pub use schema::{FORMAT, PackSource, Tier};
use schema::{Mapped, RecordRule, Until};

/// Extractor name recorded in evidence.
pub const EXTRACTOR_NAME: &str = "dviscope";
/// Extractor version recorded in evidence and covered by the pipeline digest.
pub const EXTRACTOR_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Fingerprint schema.
pub const FINGERPRINT_SCHEMA: &str = "fp/1";
/// Version of the fixed protected recognizers, normalizers and the error-like heuristic.
pub const FIXED_CODE_VERSION: &str = "protect/1 norm/1 error-like/1 bounded/1 model-main/1";

/// Bytes a rendered template keeps at most (messages and IDs are cut much shorter later).
pub const MAX_RENDER_BYTES: usize = 64 * 1024;

/// What [`Template::render`] reports in `missing` when it cut its output.
pub const RENDER_OVERFLOW: &str = "<render overflow>";

/// The one declared profile: a Verilator model with its own C++ main (no Verilator report).
pub const MODEL_MAIN_PROFILE: &str = "verilator-model-main";

/// Limits of pack validation.
pub mod limits {
    /// Pack file size.
    pub const MAX_PACK_BYTES: usize = 1024 * 1024;
    /// YAML nesting depth.
    pub const MAX_YAML_DEPTH: usize = 16;
    /// Continuation lines per record.
    pub const MAX_CONTINUATION_LINES: u32 = 200;
    /// Compiled size of one regex.
    pub const MAX_REGEX_BYTES: usize = 256 * 1024;
    /// Rules per pipeline (records, counters, verdicts, markers, project rules).
    pub const MAX_RULES: usize = 2_000;
    /// Pattern source per pipeline.
    pub const MAX_PATTERN_SOURCE: usize = 4 * 1024 * 1024;
    /// Compiled patterns per pipeline.
    pub const MAX_COMPILED_BYTES: usize = 32 * 1024 * 1024;
}

/// Why a pack or pipeline is rejected. The pack is rejected whole; the rule is named.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackError {
    /// YAML syntax or schema.
    #[error("pack {pack}: {message}")]
    Syntax {
        /// Pack (file) name.
        pack: String,
        /// Detail.
        message: String,
    },
    /// A rule is invalid.
    #[error("pack {pack}, rule {rule}: {message}")]
    Rule {
        /// Pack ID.
        pack: String,
        /// Rule ID.
        rule: String,
        /// Detail.
        message: String,
    },
    /// The pipeline as a whole is invalid.
    #[error("pipeline: {0}")]
    Pipeline(String),
}

fn rule_err(pack: &str, rule: &str, message: impl Into<String>) -> PackError {
    PackError::Rule {
        pack: pack.to_string(),
        rule: rule.to_string(),
        message: message.into(),
    }
}

/// Parses a pack file (strict YAML: no anchors or aliases, depth ≤ 16, ≤ 1 MiB).
///
/// # Errors
/// [`PackError::Syntax`] for size, YAML or schema problems.
pub fn parse(name: &str, text: &str) -> Result<PackSource, PackError> {
    let syntax = |message: String| PackError::Syntax {
        pack: name.to_string(),
        message,
    };
    if text.len() > limits::MAX_PACK_BYTES {
        return Err(syntax(format!(
            "file larger than {} bytes",
            limits::MAX_PACK_BYTES
        )));
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_depth = limits::MAX_YAML_DEPTH;
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_documents = 1;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    let source: PackSource = serde_saphyr::from_str_with_options(text, options)
        .map_err(|e| syntax(first_line(&e.to_string())))?;
    if source.format != FORMAT {
        return Err(syntax(format!(
            "format must be {FORMAT}, found {}",
            source.format
        )));
    }
    Ok(source)
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or_default().to_string()
}

/// A template with `${capture}` references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template(Vec<Seg>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Lit(String),
    /// `${name}` or `${name|default}`.
    Var(String, Option<String>),
}

impl Template {
    fn parse(text: &str) -> Result<Self, String> {
        let mut segs = vec![];
        let mut rest = text;
        while let Some(pos) = rest.find("${") {
            if pos > 0 {
                segs.push(Seg::Lit(rest[..pos].to_string()));
            }
            let after = &rest[pos + 2..];
            let end = after
                .find('}')
                .ok_or_else(|| format!("unclosed ${{ in template {text:?}"))?;
            let (name, default) = match after[..end].split_once('|') {
                Some((n, d)) => (n, Some(d.to_string())),
                None => (&after[..end], None),
            };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(format!("bad capture name {name:?} in template {text:?}"));
            }
            segs.push(Seg::Var(name.to_string(), default));
            rest = &after[end + 1..];
        }
        if !rest.is_empty() {
            segs.push(Seg::Lit(rest.to_string()));
        }
        Ok(Self(segs))
    }

    fn vars(&self) -> impl Iterator<Item = &str> {
        self.0.iter().filter_map(|s| match s {
            Seg::Var(v, _) => Some(v.as_str()),
            Seg::Lit(_) => None,
        })
    }

    /// Renders with captures; a missing capture renders empty and is reported. The output is
    /// bounded by [`MAX_RENDER_BYTES`] (cut on a character boundary) whatever the template
    /// repeats: a small pack never makes a large allocation. A cut output
    /// is reported in `missing` as [`RENDER_OVERFLOW`]: an identifier cut there could equal
    /// another one, so callers treat it as inexact.
    pub(crate) fn render(
        &self,
        caps: &BTreeMap<String, String>,
        missing: &mut Vec<String>,
    ) -> String {
        fn push(out: &mut String, s: &str, cut: &mut bool) {
            let room = MAX_RENDER_BYTES.saturating_sub(out.len());
            if s.len() <= room {
                out.push_str(s);
            } else {
                let mut end = room;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                out.push_str(&s[..end]);
                *cut = true;
            }
        }
        let mut out = String::new();
        let mut cut = false;
        for s in &self.0 {
            match s {
                Seg::Lit(l) => push(&mut out, l, &mut cut),
                Seg::Var(v, default) => match (caps.get(v), default) {
                    (Some(val), _) => push(&mut out, val, &mut cut),
                    (None, Some(d)) => push(&mut out, d, &mut cut),
                    (None, None) => missing.push(v.clone()),
                },
            }
        }
        if cut {
            missing.push(RENDER_OVERFLOW.to_string());
        }
        out
    }
}

/// A literal-or-mapped value, compiled.
#[derive(Debug, Clone)]
pub(crate) enum CMapped<T> {
    Lit(T),
    From {
        group: String,
        map: BTreeMap<String, T>,
        default: Option<T>,
    },
}

impl<T: Clone> CMapped<T> {
    pub(crate) fn resolve(&self, caps: &BTreeMap<String, String>) -> Option<T> {
        match self {
            Self::Lit(v) => Some(v.clone()),
            Self::From {
                group,
                map,
                default,
            } => caps
                .get(group)
                .and_then(|c| map.get(c).cloned())
                .or_else(|| default.clone()),
        }
    }
}

fn compile_mapped<T: Clone>(
    m: &Mapped,
    parse: impl Fn(&str) -> Option<T>,
    what: &str,
) -> Result<CMapped<T>, String> {
    let one = |s: &str| parse(s).ok_or_else(|| format!("unknown {what} {s:?}"));
    Ok(match m {
        Mapped::Literal(s) => CMapped::Lit(one(s)?),
        Mapped::From(f) => CMapped::From {
            group: f.from.clone(),
            map: f
                .map
                .iter()
                .map(|(k, v)| Ok((k.clone(), one(v)?)))
                .collect::<Result<_, String>>()?,
            default: f.default.as_deref().map(one).transpose()?,
        },
    })
}

fn mapped_group(m: &Mapped) -> Option<&str> {
    match m {
        Mapped::Literal(_) => None,
        Mapped::From(f) => Some(&f.from),
    }
}

/// Parses a severity name.
#[must_use]
pub fn severity(s: &str) -> Option<Severity> {
    Some(match s {
        "info" => Severity::Info,
        "warning" => Severity::Warning,
        "error" => Severity::Error,
        "fatal" => Severity::Fatal,
        _ => return None,
    })
}

fn framework(s: &str) -> Option<Framework> {
    Some(match s {
        "uvm" => Framework::Uvm,
        "simulator" => Framework::Simulator,
        "assertion" => Framework::Assertion,
        "svunit" => Framework::Svunit,
        "display" => Framework::Display,
        "project" => Framework::Project,
        _ => return None,
    })
}

fn kind(s: &str) -> Option<DiagKind> {
    Some(match s {
        "check" => DiagKind::Check,
        "assertion" => DiagKind::Assertion,
        "timeout" => DiagKind::Timeout,
        "crash" => DiagKind::Crash,
        "build" => DiagKind::Build,
        "x_z" => DiagKind::XZ,
        "usage" => DiagKind::Usage,
        "resource" => DiagKind::Resource,
        "license" => DiagKind::License,
        "other" => DiagKind::Other,
        _ => return None,
    })
}

fn phase(s: &str) -> Option<Phase> {
    Some(match s {
        "compile" => Phase::Compile,
        "elaborate" => Phase::Elaborate,
        "run" => Phase::Run,
        _ => return None,
    })
}

fn domain(s: &str) -> Option<CounterDomain> {
    Some(match s {
        "uvm_severity" => CounterDomain::UvmSeverity,
        "uvm_by_id" => CounterDomain::UvmById,
        "sim_tool" => CounterDomain::SimTool,
        "checks" => CounterDomain::Checks,
        "svunit" => CounterDomain::Svunit,
        "banner" => CounterDomain::Banner,
        "project" => CounterDomain::Project,
        _ => return None,
    })
}

/// Name of a counter domain as used in `domain:key` references.
#[must_use]
pub fn domain_name(d: CounterDomain) -> &'static str {
    match d {
        CounterDomain::UvmSeverity => "uvm_severity",
        CounterDomain::UvmById => "uvm_by_id",
        CounterDomain::SimTool => "sim_tool",
        CounterDomain::Checks => "checks",
        CounterDomain::Svunit => "svunit",
        CounterDomain::Banner => "banner",
        CounterDomain::Project => "project",
    }
}

fn role(s: &str) -> Option<CounterRole> {
    Some(match s {
        "failure_count" => CounterRole::FailureCount,
        "warning_count" => CounterRole::WarningCount,
        "success_count" => CounterRole::SuccessCount,
        "info" => CounterRole::Info,
        _ => return None,
    })
}

/// The verdict values packs may map to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerdictWord {
    Pass,
    Fail,
    NotApplicable,
}

fn verdict_word(s: &str) -> Option<VerdictWord> {
    Some(match s {
        "pass" => VerdictWord::Pass,
        "fail" => VerdictWord::Fail,
        "not_applicable" => VerdictWord::NotApplicable,
        _ => return None,
    })
}

/// Normalizers known to this extractor version.
pub const NORMALIZERS: &[&str] = &[
    "sv_literal",
    "hex",
    "number",
    "time",
    "path",
    "whitespace",
    "suffix_strip",
    "index_fold",
];

/// A compiled continuation matcher.
#[derive(Debug)]
pub(crate) struct CLine {
    pub(crate) re: Regex,
    pub(crate) capture: bool,
    pub(crate) append_to: Option<String>,
    pub(crate) once: bool,
    pub(crate) mandatory: bool,
}

/// A compiled typed field.
#[derive(Debug, Clone)]
pub(crate) struct CField {
    pub(crate) name: String,
    pub(crate) from: String,
    pub(crate) kind: FieldKind,
}

/// Field types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldKind {
    Text,
    Integer,
    SvLiteral,
    Time,
}

fn field_kind(s: &str) -> Option<FieldKind> {
    Some(match s {
        "text" => FieldKind::Text,
        "integer" => FieldKind::Integer,
        "sv_literal" => FieldKind::SvLiteral,
        "time" => FieldKind::Time,
        _ => return None,
    })
}

/// Significance kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Significance {
    Verbatim,
    ZeroVsNonzero,
    XVsKnown,
    Class(Vec<String>),
}

/// A compiled emit block.
#[derive(Debug)]
pub(crate) struct CEmit {
    pub(crate) framework: Framework,
    pub(crate) severity: CMapped<Severity>,
    pub(crate) diag_id: Template,
    pub(crate) checker_id: Option<Template>,
    pub(crate) checker_scope: Option<Template>,
    pub(crate) kind: CMapped<DiagKind>,
    pub(crate) phase: Option<CMapped<Phase>>,
    pub(crate) family: String,
    pub(crate) message: Template,
    pub(crate) anchor: Option<(String, Option<String>, String)>,
    pub(crate) sim_time: Option<(String, Option<String>, Option<String>)>,
    pub(crate) context: Option<Template>,
    pub(crate) identity_fields: Vec<String>,
    pub(crate) display_fields: Vec<String>,
    pub(crate) fields: Vec<CField>,
    pub(crate) message_fields: Vec<(String, Regex, FieldKind)>,
    pub(crate) significance: BTreeMap<String, Significance>,
    pub(crate) normalize: Vec<String>,
    pub(crate) normalize_for: BTreeMap<String, Vec<String>>,
    pub(crate) fatal_witness: bool,
    pub(crate) fails_run: Option<bool>,
}

/// A compiled record rule.
#[derive(Debug)]
pub(crate) struct CRecord {
    pub(crate) pack: usize,
    pub(crate) tier: Tier,
    pub(crate) prefixes: Option<Vec<String>>,
    pub(crate) start: Regex,
    pub(crate) max_lines: u32,
    pub(crate) until_blank: bool,
    pub(crate) lines: Vec<CLine>,
    pub(crate) emit: Option<CEmit>,
    /// `pack/rule@version`.
    pub(crate) qualified: String,
}

/// A compiled counter.
#[derive(Debug)]
pub(crate) struct CCounter {
    pub(crate) id: String,
    pub(crate) pack: usize,
    pub(crate) domain: CounterDomain,
    pub(crate) re: Regex,
    pub(crate) values: Vec<CCounterValue>,
    pub(crate) protected: bool,
    pub(crate) within: Option<String>,
}

/// One value of a compiled counter.
#[derive(Debug)]
pub(crate) struct CCounterValue {
    pub(crate) key: Template,
    pub(crate) from: String,
    pub(crate) role: CMapped<CounterRole>,
    pub(crate) explained_by: Option<Template>,
    pub(crate) keys: Option<Vec<String>>,
}

/// A compiled verdict source.
#[derive(Debug)]
pub(crate) struct CVerdict {
    pub(crate) pack: usize,
    pub(crate) source: dviscope_model::wire::evidence::VerdictSourceKind,
    pub(crate) re: Regex,
    pub(crate) value: CMapped<VerdictWord>,
}

/// A compiled marker.
#[derive(Debug)]
pub(crate) struct CMarker {
    pub(crate) id: String,
    pub(crate) pack: usize,
    pub(crate) re: Regex,
    pub(crate) design_loaded: Option<bool>,
    pub(crate) trailer: bool,
    pub(crate) fatal_witness: bool,
}

/// A compiled suppression.
#[derive(Debug)]
pub(crate) struct CSuppression {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) not_an_error: bool,
    pub(crate) severity: Option<Severity>,
    pub(crate) diag_ids: Vec<String>,
    pub(crate) pattern: Option<Regex>,
}

/// A compiled reconciliation template.
#[derive(Debug)]
pub(crate) struct CReconcile {
    pub(crate) template: String,
    pub(crate) counters: Vec<(CounterDomain, String)>,
    pub(crate) frameworks: Vec<Framework>,
    pub(crate) severities: Vec<Severity>,
}

/// One pack of a pipeline.
#[derive(Debug)]
pub struct CompiledPack {
    /// Pack ID.
    pub id: String,
    /// Version.
    pub version: String,
    /// Digest of the pack source bytes.
    pub digest: Digest,
    /// Tier.
    pub tier: Tier,
    /// Simulator of a simulator pack.
    pub simulator: Option<String>,
    /// Whether the simulator's exit status carries meaning (outcome row 7).
    pub exit_code_meaningful: bool,
    pub(crate) detect: Vec<Regex>,
    pub(crate) framing: Option<String>,
    pub(crate) replaces: Vec<String>,
    pub(crate) boundaries: Option<RegexSet>,
    pub(crate) sections: Vec<schema::SectionDecl>,
    pub(crate) completion: schema::Completion,
    pub(crate) reconcile: Vec<CReconcile>,
    pub(crate) tests: Vec<schema::SelfTest>,
}

/// An immutable compiled pipeline.
#[derive(Debug)]
pub struct Pipeline {
    /// Pipeline digest.
    pub digest: Digest,
    /// Packs in precedence order.
    pub packs: Vec<CompiledPack>,
    pub(crate) records: Vec<CRecord>,
    pub(crate) counters: Vec<CCounter>,
    pub(crate) verdicts: Vec<CVerdict>,
    pub(crate) markers: Vec<CMarker>,
    pub(crate) suppressions: Vec<CSuppression>,
    pub(crate) summary_set: RegexSet,
}

impl Pipeline {
    /// Compiled rules: records, counters, verdict sources, markers and suppressions (the
    /// rule check's compiled size).
    #[must_use]
    pub fn rule_count(&self) -> u64 {
        (self.records.len()
            + self.counters.len()
            + self.verdicts.len()
            + self.markers.len()
            + self.suppressions.len()) as u64
    }

    /// The project pack declaring a Verilator model's console markers (at most one).
    #[must_use]
    pub fn model_main(&self) -> Option<(&CompiledPack, &schema::ModelMainDecl)> {
        self.packs
            .iter()
            .find_map(|p| p.completion.model_main.as_ref().map(|m| (p, m)))
    }

    /// The simulator pack that declares a completion profile (the profile evidence records
    /// is the one of the simulator selected during extraction).
    #[must_use]
    pub fn pack_of_profile(&self, profile: &str) -> Option<&CompiledPack> {
        self.packs.iter().find(|p| {
            p.simulator.is_some() && p.completion.profiles.iter().any(|d| d.name == profile)
        })
    }

    /// Every record rule whose start matches the line, raw or after a simulator pack's
    /// framing, in precedence order: the first one claims the line, the others are
    /// shadowed (`rules explain`).
    #[must_use]
    pub fn start_candidates(&self, line: &str) -> Vec<String> {
        let framed: Vec<&str> = std::iter::once(line)
            .chain(
                self.packs
                    .iter()
                    .filter_map(|p| p.framing.as_deref().and_then(|f| line.strip_prefix(f))),
            )
            .collect();
        self.records
            .iter()
            .filter(|r| framed.iter().any(|t| r.start.is_match(t)))
            .map(|r| r.qualified.clone())
            .collect()
    }
}

/// Pattern budget of the pipeline being compiled: source bytes and compiled memory of
/// every regex (records, continuations, message fields, counters, verdicts, markers,
/// detection, boundaries, suppressions), charged before the regex is retained.
#[derive(Debug, Default)]
struct Budget {
    source: usize,
    compiled: usize,
}

thread_local! {
    static BUDGET: std::cell::RefCell<Budget> = std::cell::RefCell::new(Budget::default());
}

fn build_regex(pack: &str, rule: &str, pattern: &str) -> Result<Regex, PackError> {
    let err = |m: String| rule_err(pack, rule, m);
    let source = BUDGET.with(|b| {
        let mut b = b.borrow_mut();
        b.source += pattern.len();
        b.source
    });
    if source > limits::MAX_PATTERN_SOURCE {
        return Err(PackError::Pipeline(format!(
            "more than {} bytes of pattern source",
            limits::MAX_PATTERN_SOURCE
        )));
    }
    // The regex crate's program-size limit rejects one oversized pattern cheaply first;
    // the pipeline total is then the heap size of the whole engine (forward and reverse
    // automata included), measured with the same engine the regex crate uses.
    let re = RegexBuilder::new(pattern)
        .size_limit(limits::MAX_REGEX_BYTES)
        .build()
        .map_err(|e| err(format!("bad pattern: {}", first_line(&e.to_string()))))?;
    let used = regex_automata::meta::Regex::builder()
        .configure(
            regex_automata::meta::Config::new().nfa_size_limit(Some(limits::MAX_REGEX_BYTES * 16)),
        )
        .build(pattern)
        .map_err(|e| err(format!("bad pattern: {}", first_line(&e.to_string()))))?
        .memory_usage();
    let compiled = BUDGET.with(|b| {
        let mut b = b.borrow_mut();
        b.compiled += used;
        b.compiled
    });
    if compiled > limits::MAX_COMPILED_BYTES {
        return Err(PackError::Pipeline(format!(
            "patterns compile to more than {} bytes",
            limits::MAX_COMPILED_BYTES
        )));
    }
    Ok(re)
}

/// Builds a regex set and charges its compiled size to the pipeline budget.
fn build_set(patterns: &[String]) -> Result<RegexSet, String> {
    let set = RegexSetBuilder::new(patterns)
        .size_limit(limits::MAX_COMPILED_BYTES)
        .build()
        .map_err(|e| first_line(&e.to_string()))?;
    let used = regex_automata::meta::Regex::builder()
        .configure(
            regex_automata::meta::Config::new().nfa_size_limit(Some(limits::MAX_COMPILED_BYTES)),
        )
        .build_many(patterns)
        .map_err(|e| first_line(&e.to_string()))?
        .memory_usage();
    let compiled = BUDGET.with(|b| {
        let mut b = b.borrow_mut();
        b.compiled += used;
        b.compiled
    });
    if compiled > limits::MAX_COMPILED_BYTES {
        return Err(format!(
            "patterns compile to more than {} bytes",
            limits::MAX_COMPILED_BYTES
        ));
    }
    Ok(set)
}

fn group_names(re: &Regex) -> impl Iterator<Item = String> + '_ {
    re.capture_names().flatten().map(str::to_string)
}

/// Checks that every string a `start` pattern can match begins with one of the declared
/// literal prefixes, so prefix dispatch never misses a start.
fn check_prefixes(
    pack: &str,
    rule: &str,
    start: &str,
    prefixes: &[String],
) -> Result<(), PackError> {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    if prefixes.is_empty() || prefixes.iter().any(String::is_empty) {
        return Err(rule_err(pack, rule, "prefix must be a non-empty literal"));
    }
    let hir =
        regex_syntax::parse(start).map_err(|e| rule_err(pack, rule, first_line(&e.to_string())))?;
    let seq = Extractor::new().kind(ExtractKind::Prefix).extract(&hir);
    let lits = seq.literals().ok_or_else(|| {
        rule_err(
            pack,
            rule,
            "prefix declared but the start pattern has no literal prefix",
        )
    })?;
    if !hir
        .properties()
        .look_set_prefix()
        .contains(regex_syntax::hir::Look::Start)
    {
        return Err(rule_err(
            pack,
            rule,
            "a start with a prefix must be anchored with ^ on every alternative",
        ));
    }
    for lit in lits {
        let bytes = lit.as_bytes();
        let covered = prefixes.iter().any(|p| {
            let p = p.as_bytes();
            bytes.len() >= p.len() && &bytes[..p.len()] == p
        });
        if !covered {
            return Err(rule_err(
                pack,
                rule,
                format!(
                    "prefix is not a literal prefix of start (start can begin with {:?})",
                    String::from_utf8_lossy(bytes)
                ),
            ));
        }
    }
    Ok(())
}

struct Ctx<'a> {
    pack: &'a str,
    pack_idx: usize,
    tier: Tier,
    version: &'a str,
    default_normalize: &'a [String],
    pattern_bytes: usize,
}

fn compile_record(
    c: &mut Ctx<'_>,
    r: &RecordRule,
    fails_run: Option<bool>,
) -> Result<CRecord, PackError> {
    let err = |m: String| rule_err(c.pack, &r.id, m);
    c.pattern_bytes += r.start.len();
    let start = build_regex(c.pack, &r.id, &r.start)?;
    let prefixes = r.prefix.as_ref().map(schema::OneOrMany::to_vec);
    if let Some(p) = &prefixes {
        check_prefixes(c.pack, &r.id, &r.start, p)?;
    }
    let mut known: BTreeSet<String> = group_names(&start).collect();
    let (max_lines, until_blank, mut lines) = match &r.continuation {
        None => (0, false, vec![]),
        Some(cont) => {
            if cont.max_lines == 0 || cont.max_lines > limits::MAX_CONTINUATION_LINES {
                return Err(err(format!(
                    "max_lines must be 1..={}",
                    limits::MAX_CONTINUATION_LINES
                )));
            }
            let mut out = vec![];
            let mut seen_optional = false;
            for (i, l) in cont.lines.iter().enumerate() {
                c.pattern_bytes += l.pattern.len();
                if l.mandatory && seen_optional {
                    return Err(err(format!(
                        "continuation line {i}: mandatory lines must come first"
                    )));
                }
                seen_optional |= !l.mandatory;
                let re = build_regex(c.pack, &r.id, &l.pattern)?;
                if l.capture {
                    known.extend(group_names(&re));
                }
                if let Some(a) = &l.append_to {
                    known.insert(a.clone());
                }
                out.push(CLine {
                    re,
                    capture: l.capture,
                    append_to: l.append_to.clone(),
                    once: l.once,
                    mandatory: l.mandatory,
                });
            }
            (cont.max_lines, cont.until == Until::Blank, out)
        }
    };
    if lines.iter().filter(|l| l.mandatory).count() > max_lines as usize {
        return Err(err("more mandatory lines than max_lines".into()));
    }
    let emit = match &r.emit {
        // A record without an emit is consumed silently: it cannot fail the run, so a rule
        // that says it does is refused.
        None if fails_run == Some(true) => {
            return Err(err(
                "fails_run: true needs an emit (a failure to account)".into()
            ));
        }
        None => None,
        Some(e) => Some(compile_emit(c, &r.id, e, &known, fails_run)?),
    };
    lines.shrink_to_fit();
    Ok(CRecord {
        pack: c.pack_idx,
        tier: c.tier,
        prefixes,
        start,
        max_lines,
        until_blank,
        lines,
        emit,
        qualified: format!("{}/{}@{}", c.pack, r.id, c.version),
    })
}

#[allow(clippy::too_many_lines)] // one check per emit key, in declaration order
fn compile_emit(
    c: &mut Ctx<'_>,
    rule: &str,
    e: &schema::Emit,
    known: &BTreeSet<String>,
    fails_run: Option<bool>,
) -> Result<CEmit, PackError> {
    let err = |m: String| rule_err(c.pack, rule, m);
    let tpl = |s: &str| -> Result<Template, PackError> {
        let t = Template::parse(s).map_err(err)?;
        for v in t.vars() {
            if !known.contains(v) {
                return Err(err(format!("template refers to unknown capture {v:?}")));
            }
        }
        Ok(t)
    };
    let need = |g: &str| -> Result<(), PackError> {
        if known.contains(g) {
            Ok(())
        } else {
            Err(err(format!("unknown capture {g:?}")))
        }
    };
    for m in [Some(&e.severity), e.kind.as_ref(), e.phase.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(g) = mapped_group(m) {
            need(g)?;
        }
    }
    let fw = framework(&e.framework)
        .ok_or_else(|| err(format!("unknown framework {:?}", e.framework)))?;
    let family = match &e.family {
        Some(f) => {
            if !["uvm-app", "tool", "assertion", "build"].contains(&f.as_str()) {
                return Err(err(format!("unknown family {f:?}")));
            }
            f.clone()
        }
        None => match fw {
            Framework::Uvm | Framework::Project => "uvm-app",
            Framework::Assertion => "assertion",
            _ => "tool",
        }
        .to_string(),
    };
    let anchor = match &e.anchor {
        None => None,
        Some(a) => {
            need(&a.path)?;
            if let Some(l) = &a.line {
                need(l)?;
            }
            if !["full", "truncated", "auto"].contains(&a.form.as_str()) {
                return Err(err(format!("unknown anchor form {:?}", a.form)));
            }
            Some((a.path.clone(), a.line.clone(), a.form.clone()))
        }
    };
    let sim_time = match &e.sim_time {
        None => None,
        Some(t) => {
            need(&t.value)?;
            if let Some(u) = &t.unit {
                need(u)?;
            }
            Some((t.value.clone(), t.unit.clone(), t.unit_literal.clone()))
        }
    };
    for f in e.identity_fields.iter().chain(&e.display_fields) {
        need(f)?;
    }
    if let Some(f) = e
        .identity_fields
        .iter()
        .find(|f| e.display_fields.contains(f))
    {
        return Err(err(format!(
            "{f:?} is both an identity and a display field"
        )));
    }
    let mut fields = vec![];
    for f in &e.fields {
        let from = f.from.clone().unwrap_or_else(|| f.name.clone());
        need(&from)?;
        fields.push(CField {
            name: f.name.clone(),
            from,
            kind: field_kind(&f.kind)
                .ok_or_else(|| err(format!("unknown field type {:?}", f.kind)))?,
        });
    }
    let mut message_fields = vec![];
    for f in &e.fields_from_message {
        c.pattern_bytes += f.pattern.len();
        let re = build_regex(c.pack, rule, &f.pattern)?;
        if !group_names(&re).any(|g| g == "v") {
            return Err(err(format!(
                "message field {:?} needs a group named v",
                f.name
            )));
        }
        message_fields.push((
            f.name.clone(),
            re,
            field_kind(&f.kind).ok_or_else(|| err(format!("unknown field type {:?}", f.kind)))?,
        ));
    }
    let mut significance = BTreeMap::new();
    for (name, sig) in &e.significance {
        if !fields.iter().any(|f| &f.name == name) && !message_fields.iter().any(|f| &f.0 == name) {
            return Err(err(format!("significance of undeclared field {name:?}")));
        }
        let s = match sig.as_str() {
            "verbatim" => Significance::Verbatim,
            "zero_vs_nonzero" => Significance::ZeroVsNonzero,
            "x_vs_known" => Significance::XVsKnown,
            other => match other.strip_prefix("class:") {
                Some(list) if !list.is_empty() => {
                    Significance::Class(list.split('|').map(str::to_string).collect())
                }
                _ => return Err(err(format!("unknown significance {other:?}"))),
            },
        };
        significance.insert(name.clone(), s);
    }
    let normalize = e
        .normalize
        .clone()
        .unwrap_or_else(|| c.default_normalize.to_vec());
    for n in normalize.iter().chain(e.normalize_for.values().flatten()) {
        if !NORMALIZERS.contains(&n.as_str()) {
            return Err(err(format!("unknown normalizer {n:?}")));
        }
    }
    let sev = compile_mapped(&e.severity, severity, "severity").map_err(err)?;
    // Diagnostics below warning never enter accounting, so a rule that fails the run must
    // never resolve below it: every literal or mapped severity, and the default (an
    // unmapped capture resolves to error). Otherwise a declared failure would vanish.
    if fails_run == Some(true) {
        let possible: Vec<Severity> = match &sev {
            CMapped::Lit(v) => vec![*v],
            CMapped::From { map, default, .. } => map
                .values()
                .copied()
                .chain(std::iter::once(default.unwrap_or(Severity::Error)))
                .collect(),
        };
        if possible.iter().any(|v| *v < Severity::Warning) {
            return Err(err(
                "fails_run: true needs a severity of warning or above (every mapped value)".into(),
            ));
        }
    }
    Ok(CEmit {
        framework: fw,
        severity: sev,
        diag_id: tpl(&e.diag_id)?,
        checker_id: e.checker_id.as_deref().map(tpl).transpose()?,
        checker_scope: e.checker_scope.as_deref().map(tpl).transpose()?,
        kind: match &e.kind {
            Some(k) => compile_mapped(k, kind, "kind").map_err(err)?,
            None => CMapped::Lit(DiagKind::Other),
        },
        phase: e
            .phase
            .as_ref()
            .map(|p| compile_mapped(p, phase, "phase").map_err(err))
            .transpose()?,
        family,
        message: tpl(&e.message)?,
        anchor,
        sim_time,
        context: e.context.as_deref().map(tpl).transpose()?,
        identity_fields: e.identity_fields.clone(),
        display_fields: e.display_fields.clone(),
        fields,
        message_fields,
        significance,
        normalize,
        normalize_for: e.normalize_for.clone(),
        fatal_witness: e.fatal_witness,
        fails_run,
    })
}

fn split_counter_ref(r: &str) -> Option<(CounterDomain, String)> {
    let (d, k) = r.split_once(':')?;
    Some((domain(d)?, k.to_string()))
}

/// Whether some counter rule of the pack can produce `domain:key`: a literal key template
/// equal to it, or a template whose literal parts it contains in order.
fn declares_counter(pack: &PackSource, d: CounterDomain, key: &str) -> bool {
    // A literal key template must equal the reference; a template with captures must list
    // the keys it can produce (`keys`), and the reference must be one of them.
    pack.counters
        .iter()
        .filter(|k| domain(&k.domain) == Some(d))
        .any(|k| {
            k.values.iter().any(|v| {
                Template::parse(&v.key).is_ok_and(|t| {
                    let literal = t.vars().next().is_none();
                    if literal {
                        key_matcher(&t).is_some_and(|re| re.is_match(key))
                    } else {
                        v.keys
                            .as_ref()
                            .is_some_and(|ks| ks.iter().any(|k| k == key))
                            && key_matcher(&t).is_some_and(|re| re.is_match(key))
                    }
                })
            })
        })
}

/// Variables a counter key template may hold (each capture at most once).
const MAX_KEY_VARS: usize = 8;

/// A linear-time matcher of the keys a template can render: literals in place, each
/// variable a non-empty string. `None` when the template repeats a capture or has too many
/// variables (rejected at validation, see [`check_key_template`]).
fn key_matcher(t: &Template) -> Option<Regex> {
    let mut seen = BTreeSet::new();
    let mut pattern = String::from("^");
    for seg in &t.0 {
        match seg {
            Seg::Lit(l) => pattern.push_str(&regex::escape(l)),
            Seg::Var(v, _) => {
                if !seen.insert(v.as_str()) || seen.len() > MAX_KEY_VARS {
                    return None;
                }
                pattern.push_str("(?s:.+)");
            }
        }
    }
    pattern.push('$');
    Regex::new(&pattern).ok()
}

/// Validates a counter key template: each capture at most once, at most
/// [`MAX_KEY_VARS`] variables (references to its keys are then checked exactly).
fn check_key_template(t: &Template) -> Result<(), String> {
    key_matcher(t).map(|_| ()).ok_or_else(|| {
        format!("a counter key uses each capture at most once and at most {MAX_KEY_VARS} variables")
    })
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn valid_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// A pack source with its original text (the digest covers the bytes).
#[derive(Debug, Clone)]
pub struct PackInput {
    /// Name for messages (file name).
    pub name: String,
    /// Source text.
    pub text: String,
}

/// Compiles packs into a pipeline. Packs are ordered by tier, then by the given order.
///
/// # Errors
/// The first invalid pack or rule, or a pipeline limit.
#[allow(clippy::too_many_lines)] // one validation pass per declaration kind, kept together
pub fn compile(inputs: &[PackInput]) -> Result<Pipeline, PackError> {
    let mut parsed = vec![];
    for i in inputs {
        let src = parse(&i.name, &i.text)?;
        parsed.push((src, Digest::of_bytes(i.text.as_bytes())));
    }
    // Stable sort: tier, then input order.
    parsed.sort_by_key(|(s, _)| s.tier);
    let mut ids = BTreeSet::new();
    for (s, _) in &parsed {
        if !ids.insert(s.pack.clone()) {
            return Err(PackError::Pipeline(format!("pack {} given twice", s.pack)));
        }
    }
    BUDGET.with(|b| *b.borrow_mut() = Budget::default());
    let mut packs = vec![];
    let mut records = vec![];
    let mut project_records = vec![];
    let mut counters = vec![];
    let mut verdicts = vec![];
    let mut markers = vec![];
    let mut suppressions = vec![];
    let mut pattern_bytes = 0usize;
    let mut rule_count = 0usize;
    for (idx, (s, digest)) in parsed.iter().enumerate() {
        let pack = s.pack.as_str();
        let perr = |m: String| rule_err(pack, "-", m);
        if !valid_id(pack) {
            return Err(perr("pack ID must be [a-z0-9_-]+".into()));
        }
        if !valid_version(&s.version) {
            return Err(perr("version must be MAJOR.MINOR.PATCH".into()));
        }
        match (s.tier, &s.simulator) {
            (Tier::Simulator, None) => {
                return Err(perr("a simulator pack names its simulator".into()));
            }
            (Tier::Simulator, Some(_)) | (_, None) => {}
            (_, Some(_)) => return Err(perr("only simulator packs name a simulator".into())),
        }
        if s.framing.is_some() && s.tier != Tier::Simulator {
            return Err(perr("only simulator packs declare framing".into()));
        }
        if !s.rules.is_empty() && s.tier != Tier::Project {
            return Err(perr("only project packs declare rules".into()));
        }
        for n in &s.normalize {
            if !NORMALIZERS.contains(&n.as_str()) {
                return Err(perr(format!("unknown normalizer {n:?}")));
            }
        }
        let mut rule_ids = BTreeSet::new();
        let mut c = Ctx {
            pack,
            pack_idx: idx,
            tier: s.tier,
            version: &s.version,
            default_normalize: &s.normalize,
            pattern_bytes: 0,
        };
        for r in &s.records {
            if !rule_ids.insert(r.id.clone()) {
                return Err(rule_err(pack, &r.id, "duplicate rule ID"));
            }
            records.push(compile_record(&mut c, r, None)?);
        }
        for pr in &s.rules {
            if !rule_ids.insert(pr.id.clone()) {
                return Err(rule_err(pack, &pr.id, "duplicate rule ID"));
            }
            if !valid_version(&pr.version) {
                return Err(rule_err(pack, &pr.id, "version must be MAJOR.MINOR.PATCH"));
            }
            match pr.kind.as_str() {
                "project_pattern" => {
                    let r = pr
                        .record
                        .as_ref()
                        .ok_or_else(|| rule_err(pack, &pr.id, "a project pattern needs record"))?;
                    let mut rec = compile_record(&mut c, r, pr.fails_run)?;
                    rec.tier = Tier::Project;
                    rec.qualified = format!("{pack}/{}@{}", pr.id, pr.version);
                    // Project rules come before every pack, in pack order
                    // and declaration order.
                    project_records.push(rec);
                }
                "suppression" => {
                    let not_an_error = match pr.action.as_deref() {
                        Some("not_an_error") => true,
                        Some("severity_override") => false,
                        _ => {
                            return Err(rule_err(
                                pack,
                                &pr.id,
                                "action must be not_an_error or severity_override",
                            ));
                        }
                    };
                    let sev = pr
                        .severity
                        .as_deref()
                        .map(|v| {
                            severity(v).ok_or_else(|| rule_err(pack, &pr.id, "unknown severity"))
                        })
                        .transpose()?;
                    if !not_an_error && sev.is_none() {
                        return Err(rule_err(pack, &pr.id, "severity_override needs severity"));
                    }
                    if pr.diag_ids.is_empty() && pr.pattern.is_none() {
                        return Err(rule_err(
                            pack,
                            &pr.id,
                            "a suppression needs diag_ids or match",
                        ));
                    }
                    let pattern = pr
                        .pattern
                        .as_deref()
                        .map(|p| build_regex(pack, &pr.id, p))
                        .transpose()?;
                    suppressions.push(CSuppression {
                        id: pr.id.clone(),
                        version: pr.version.clone(),
                        not_an_error,
                        severity: sev,
                        diag_ids: pr.diag_ids.clone(),
                        pattern,
                    });
                }
                other => {
                    return Err(rule_err(
                        pack,
                        &pr.id,
                        format!("unknown rule kind {other:?}"),
                    ));
                }
            }
        }
        for k in &s.counters {
            if !rule_ids.insert(k.id.clone()) {
                return Err(rule_err(pack, &k.id, "duplicate rule ID"));
            }
            c.pattern_bytes += k.pattern.len();
            let re = build_regex(pack, &k.id, &k.pattern)?;
            let groups: BTreeSet<String> = group_names(&re).collect();
            let mut values = vec![];
            for v in &k.values {
                let key = Template::parse(&v.key).map_err(|m| rule_err(pack, &k.id, m))?;
                check_key_template(&key).map_err(|m| rule_err(pack, &k.id, m))?;
                for g in key
                    .vars()
                    .chain([v.from.as_str()])
                    .chain(mapped_group(&v.role))
                {
                    if !groups.contains(g) {
                        return Err(rule_err(pack, &k.id, format!("unknown capture {g:?}")));
                    }
                }
                let explained_by = v
                    .explained_by
                    .as_deref()
                    .map(|t| Template::parse(t).map_err(|m| rule_err(pack, &k.id, m)))
                    .transpose()?;
                for g in explained_by.iter().flat_map(Template::vars) {
                    if !groups.contains(g) {
                        return Err(rule_err(pack, &k.id, format!("unknown capture {g:?}")));
                    }
                }
                values.push(CCounterValue {
                    key,
                    from: v.from.clone(),
                    role: compile_mapped(&v.role, role, "role")
                        .map_err(|m| rule_err(pack, &k.id, m))?,
                    explained_by,
                    keys: v.keys.clone(),
                });
            }
            counters.push(CCounter {
                id: k.id.clone(),
                pack: idx,
                domain: domain(&k.domain).ok_or_else(|| {
                    rule_err(pack, &k.id, format!("unknown domain {:?}", k.domain))
                })?,
                re,
                values,
                protected: k.protected,
                within: match &k.within {
                    Some(w) if !s.sections.iter().any(|sec| &sec.id == w) => {
                        return Err(rule_err(
                            pack,
                            &k.id,
                            format!("within names unknown section {w:?}"),
                        ));
                    }
                    w => w.clone(),
                },
            });
        }
        for v in &s.verdicts {
            if !rule_ids.insert(v.id.clone()) {
                return Err(rule_err(pack, &v.id, "duplicate rule ID"));
            }
            let source = match v.source.as_str() {
                "banner" => K::Banner,
                "test_result" => K::TestResult,
                "svunit_runner" => K::SvunitRunner,
                "sim_totals" => K::SimTotals,
                other => {
                    return Err(rule_err(
                        pack,
                        &v.id,
                        format!("unknown verdict source {other:?}"),
                    ));
                }
            };
            c.pattern_bytes += v.pattern.len();
            let re = build_regex(pack, &v.id, &v.pattern)?;
            if let Some(g) = mapped_group(&v.value)
                && !group_names(&re).any(|n| n == g)
            {
                return Err(rule_err(pack, &v.id, format!("unknown capture {g:?}")));
            }
            verdicts.push(CVerdict {
                pack: idx,
                source,
                re,
                value: compile_mapped(&v.value, verdict_word, "verdict")
                    .map_err(|m| rule_err(pack, &v.id, m))?,
            });
        }
        for m in &s.markers {
            if !rule_ids.insert(m.id.clone()) {
                return Err(rule_err(pack, &m.id, "duplicate rule ID"));
            }
            // Counter references are `domain:key`; a marker ID never looks like one, so a
            // requirement names a marker or a counter, never both.
            if m.id.contains(':') {
                return Err(rule_err(pack, &m.id, "marker IDs may not contain ':'"));
            }
            c.pattern_bytes += m.pattern.len();
            markers.push(CMarker {
                id: m.id.clone(),
                pack: idx,
                re: build_regex(pack, &m.id, &m.pattern)?,
                design_loaded: m.design_loaded,
                trailer: m.trailer,
                fatal_witness: m.fatal_witness,
            });
        }
        let mut section_ids = BTreeSet::new();
        for sec in &s.sections {
            if !section_ids.insert(sec.id.clone()) || rule_ids.contains(&sec.id) {
                return Err(rule_err(pack, &sec.id, "duplicate ID"));
            }
            if !s.markers.iter().any(|m| m.id == sec.open) {
                return Err(rule_err(
                    pack,
                    &sec.id,
                    format!("opening marker {:?} not in the pack", sec.open),
                ));
            }
            for r in sec
                .requires
                .iter()
                .chain(sec.verdict.iter().flat_map(|v| v.fail_if_nonzero.iter()))
            {
                let counter_ok =
                    split_counter_ref(r).is_some_and(|(d, k)| declares_counter(s, d, &k));
                if !counter_ok && !s.markers.iter().any(|m| &m.id == r) {
                    return Err(rule_err(
                        pack,
                        &sec.id,
                        format!("unknown requirement {r:?}"),
                    ));
                }
            }
            if let Some(v) = &sec.verdict {
                if v.source != "uvm_summary" {
                    return Err(rule_err(pack, &sec.id, "section verdicts are uvm_summary"));
                }
                // The verdict is computed when the section completes: every counter it
                // reads must be one of the section's requirements.
                if let Some(c) = v.fail_if_nonzero.iter().find(|c| !sec.requires.contains(c)) {
                    return Err(rule_err(
                        pack,
                        &sec.id,
                        format!("verdict counter {c:?} must also be in requires"),
                    ));
                }
                if let Some(c) = v.fail_if_nonzero.iter().find(|c| {
                    !split_counter_ref(c).is_some_and(|(d, k)| declares_counter(s, d, &k))
                }) {
                    return Err(rule_err(
                        pack,
                        &sec.id,
                        format!("verdict reads {c:?}, which is not a counter of the pack"),
                    ));
                }
            }
        }
        let mut profile_names = BTreeSet::new();
        for p in &s.completion.profiles {
            if s.tier != Tier::Simulator {
                return Err(perr("only simulator packs declare profiles".into()));
            }
            if !profile_names.insert(p.name.as_str()) {
                return Err(rule_err(pack, &p.name, "duplicate profile name"));
            }
            if p.select == schema::ProfileSelect::Declared
                && (p.name != MODEL_MAIN_PROFILE
                    || p.subject != "simulation"
                    || s.simulator.as_deref() != Some("verilator")
                    || p.early_fatal)
            {
                return Err(rule_err(
                    pack,
                    &p.name,
                    format!(
                        "the only declared profile is the Verilator pack's simulation profile                          {MODEL_MAIN_PROFILE}, without early-fatal completion"
                    ),
                ));
            }
            if !["build", "simulation"].contains(&p.subject.as_str()) {
                return Err(rule_err(
                    pack,
                    &p.name,
                    "subject must be build or simulation",
                ));
            }
            for r in p.requires.iter().flat_map(|r| r.split('|')) {
                if !rule_ids.contains(r) && !section_ids.contains(r) {
                    return Err(rule_err(
                        pack,
                        &p.name,
                        format!("unknown requirement {r:?}"),
                    ));
                }
            }
        }
        for subject in s.completion.profiles.iter().map(|p| p.subject.as_str()) {
            if !s
                .completion
                .profiles
                .iter()
                .any(|p| p.subject == subject && p.select == schema::ProfileSelect::Default)
            {
                return Err(perr(format!("no default profile for subject {subject}")));
            }
        }
        if let Some(mm) = &s.completion.model_main {
            let merr = |m: String| rule_err(pack, "model_main", m);
            if s.tier != Tier::Project {
                return Err(merr("only project packs declare model_main".into()));
            }
            if mm.trailer.is_empty() {
                return Err(merr("trailer must not be empty".into()));
            }
            let mut seen = BTreeSet::new();
            for m in std::iter::once(&mm.start).chain(&mm.trailer) {
                if !s.markers.iter().any(|k| &k.id == m) {
                    return Err(merr(format!("{m:?} is not a marker of the pack")));
                }
                if !seen.insert(m.as_str()) {
                    return Err(merr(format!("marker {m:?} named twice")));
                }
            }
        }
        for r in &s.completion.requires_when_active {
            if !section_ids.contains(r) {
                return Err(perr(format!(
                    "requires_when_active names unknown section {r:?}"
                )));
            }
        }
        let mut reconcile = vec![];
        for r in &s.reconcile {
            let rerr = |m: String| rule_err(pack, &r.template, m);
            if !["uvm_errors", "questa_sim_errors"].contains(&r.template.as_str()) {
                return Err(rerr("unknown reconciliation template".into()));
            }
            let counters = r
                .counters
                .iter()
                .map(|c| {
                    split_counter_ref(c).ok_or_else(|| rerr(format!("bad counter reference {c:?}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (d, key) in &counters {
                if !declares_counter(s, *d, key) {
                    return Err(rerr(format!(
                        "no counter of the pack can produce {}:{key}",
                        domain_name(*d)
                    )));
                }
            }
            let frameworks = r
                .frameworks
                .iter()
                .map(|f| framework(f).ok_or_else(|| rerr(format!("unknown framework {f:?}"))))
                .collect::<Result<Vec<_>, _>>()?;
            let severities = r
                .severities
                .iter()
                .map(|v| severity(v).ok_or_else(|| rerr(format!("unknown severity {v:?}"))))
                .collect::<Result<Vec<_>, _>>()?;
            if counters.is_empty() || frameworks.is_empty() || severities.is_empty() {
                return Err(rerr(
                    "counters, frameworks and severities must not be empty".into(),
                ));
            }
            reconcile.push(CReconcile {
                template: r.template.clone(),
                counters,
                frameworks,
                severities,
            });
        }
        let mut detect = vec![];
        for d in &s.detect {
            c.pattern_bytes += d.len();
            detect.push(build_regex(pack, "detect", d)?);
        }
        let boundaries = if s.boundaries.is_empty() {
            None
        } else {
            for b in &s.boundaries {
                build_regex(pack, "boundaries", b)?;
            }
            Some(build_set(&s.boundaries).map_err(|e| rule_err(pack, "boundaries", e))?)
        };
        pattern_bytes += c.pattern_bytes;
        rule_count += rule_ids.len();
        packs.push(CompiledPack {
            id: s.pack.clone(),
            version: s.version.clone(),
            digest: digest.clone(),
            tier: s.tier,
            simulator: s.simulator.clone(),
            exit_code_meaningful: s.exit_code_meaningful.unwrap_or(false),
            detect,
            framing: s.framing.as_ref().map(|f| f.strip_prefix.clone()),
            replaces: s.replaces.clone(),
            boundaries,
            sections: s.sections.clone(),
            completion: s.completion.clone(),
            reconcile,
            tests: s.tests.clone(),
        });
    }
    project_records.extend(records);
    let records = project_records;
    if rule_count > limits::MAX_RULES {
        return Err(PackError::Pipeline(format!(
            "more than {} rules",
            limits::MAX_RULES
        )));
    }
    if pattern_bytes > limits::MAX_PATTERN_SOURCE {
        return Err(PackError::Pipeline(format!(
            "more than {} bytes of pattern source",
            limits::MAX_PATTERN_SOURCE
        )));
    }
    // Sections named by replaces must exist in some pack.
    for p in &packs {
        for r in &p.replaces {
            if !packs.iter().any(|q| q.sections.iter().any(|s| &s.id == r)) {
                return Err(PackError::Pipeline(format!(
                    "pack {} replaces unknown section {r}",
                    p.id
                )));
            }
        }
    }
    // Evidence records a completion profile by name and the server resolves the simulator
    // (and whether its exit code means anything) from that name: a name declared by two
    // packs could be attributed to the wrong one.
    let mut profiles = BTreeSet::new();
    for pk in &packs {
        for pr in &pk.completion.profiles {
            if !profiles.insert(pr.name.as_str()) {
                return Err(PackError::Pipeline(format!(
                    "completion profile {} is declared by more than one pack",
                    pr.name
                )));
            }
        }
    }
    if packs
        .iter()
        .filter(|p| p.completion.model_main.is_some())
        .count()
        > 1
    {
        return Err(PackError::Pipeline(
            "model_main is declared by more than one pack".into(),
        ));
    }
    let digest = pipeline_digest(&packs)?;
    // One prefilter over every marker, verdict and counter pattern (in that order): the
    // pre-pass runs capturing regexes only for the lines this set matches.
    let summary_patterns: Vec<String> = markers
        .iter()
        .map(|m| m.re.as_str().to_string())
        .chain(verdicts.iter().map(|v| v.re.as_str().to_string()))
        .chain(counters.iter().map(|k| k.re.as_str().to_string()))
        .collect();
    let summary_set =
        build_set(&summary_patterns).map_err(|e| PackError::Pipeline(first_line(&e)))?;
    Ok(Pipeline {
        digest,
        packs,
        records,
        counters,
        verdicts,
        markers,
        suppressions,
        summary_set,
    })
}

fn pipeline_digest(packs: &[CompiledPack]) -> Result<Digest, PackError> {
    let list: Vec<_> = packs
        .iter()
        .map(|p| json!({"id": p.id, "version": p.version, "digest": p.digest.as_str()}))
        .collect();
    digest_of(&json!({
        "schema": "dviscope.pipeline/1",
        "extractor": {"name": EXTRACTOR_NAME, "version": EXTRACTOR_VERSION},
        "fixed_code": FIXED_CODE_VERSION,
        "fingerprint": FINGERPRINT_SCHEMA,
        "packs": list,
    }))
    .map_err(|e| PackError::Pipeline(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rendering is bounded whatever the template repeats, cut on a
    /// character boundary.
    #[test]
    fn rendering_is_bounded() {
        let t = Template::parse(&"${m}".repeat(20_000)).unwrap_or_else(|e| panic!("{e}"));
        let caps: BTreeMap<String, String> = [("m".to_string(), "é".repeat(5_000))].into();
        let out = t.render(&caps, &mut vec![]);
        assert!(out.len() <= MAX_RENDER_BYTES && out.len() > MAX_RENDER_BYTES - 4);
        let small = Template::parse("a${m}b").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            small.render(&caps, &mut vec![]),
            format!("a{}b", "é".repeat(5_000))
        );
    }

    fn pack(body: &str) -> PackInput {
        PackInput {
            name: "t.yaml".into(),
            text: format!(
                "format: dviscope.rules/1.0\npack: t\nversion: 1.0.0\ntier: project\n{body}"
            ),
        }
    }

    #[test]
    fn prefix_must_cover_every_start() {
        let ok = pack(
            "records:\n  - id: a\n    prefix: ['ERR-', 'WRN-']\n    start: '^(?P<s>ERR|WRN)-(?P<m>.*)$'\n",
        );
        assert!(compile(&[ok]).is_ok());
        let bad = pack(
            "records:\n  - id: a\n    prefix: 'ERR-'\n    start: '^(?P<s>ERR|WRN)-(?P<m>.*)$'\n",
        );
        let e = compile(&[bad])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(e.contains("rule a") && e.contains("literal prefix"), "{e}");
        let unanchored = pack("records:\n  - id: a\n    prefix: 'X'\n    start: '.*'\n");
        assert!(compile(&[unanchored]).is_err());
    }

    #[test]
    fn anchors_aliases_and_unknown_keys_are_rejected() {
        let alias = pack("x: &a 1\nboundaries: [*a]\n");
        assert!(compile(&[alias]).is_err());
        let unknown = pack("record: []\n");
        assert!(compile(&[unknown]).is_err());
        let deep = pack(&format!(
            "boundaries: {}x{}\n",
            "[".repeat(20),
            "]".repeat(20)
        ));
        assert!(compile(&[deep]).is_err());
    }

    #[test]
    fn templates_name_existing_captures() {
        let bad = pack(
            "records:\n  - id: a\n    start: '^E (?P<m>.*)$'\n    emit: {framework: project, severity: error, diag_id: 'x:${nope}', message: '${m}'}\n",
        );
        let e = compile(&[bad])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(e.contains("unknown capture"), "{e}");
    }

    #[test]
    fn limits_are_enforced() {
        let many = pack(
            "records:\n  - id: a\n    start: '^E'\n    continuation: {max_lines: 201, lines: [{match: '.*'}]}\n",
        );
        assert!(compile(&[many]).is_err());
        let big = PackInput {
            name: "big".into(),
            text: format!(
                "format: dviscope.rules/1.0\n#{}\n",
                "x".repeat(limits::MAX_PACK_BYTES)
            ),
        };
        assert!(compile(&[big]).is_err());
    }

    #[test]
    fn digest_covers_pack_bytes_and_order() {
        let a = pack("boundaries: ['^A']\n");
        let mut b = a.clone();
        b.text.push_str("# comment\n");
        let da = compile(std::slice::from_ref(&a)).map(|p| p.digest).ok();
        let db = compile(&[b]).map(|p| p.digest).ok();
        assert!(da.is_some() && da != db);
    }
}
