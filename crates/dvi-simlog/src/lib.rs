//! Simulator log helpers shared by DVIScope and DVICode.
//!
//! Scope: lexical simulator identification, source-location parsing and
//! compile-command parsing, with paths kept exactly as written. It knows nothing about
//! diagnostics, signatures or DVIScope types and depends on no DVIScope crate. The location
//! and compile parsers are ported from DVICode (`logparse.ts`, `simlog.rs`).

#![warn(clippy::pedantic)]

pub mod compile;
pub mod location;

/// A simulator family recognized from log text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Simulator {
    /// Siemens Questa (also `ModelSim`).
    Questa,
    /// Synopsys VCS.
    Vcs,
    /// Verilator.
    Verilator,
}

impl Simulator {
    /// The simulator a log line identifies lexically (a banner or a tool-specific message
    /// form), if any. Detection looks at a few early lines; the first answer wins. Vendor
    /// banners are not matched here (they are not published; packs may detect them privately).
    #[must_use]
    pub fn detect(line: &str) -> Option<Self> {
        let l = line.trim_start();
        let body = l.strip_prefix("# ").unwrap_or(l);
        if body.starts_with("Questa")
            || body.starts_with("ModelSim")
            || body.starts_with("** ") && body.contains(": (v")
            || l.starts_with("# vsim ")
        {
            Some(Self::Questa)
        } else if l.starts_with("Command: vcs")
            || l.starts_with("Error-[")
            || l.starts_with("Warning-[")
            || l.starts_with("Lint-[")
        {
            Some(Self::Vcs)
        } else if l.starts_with("%Error")
            || l.starts_with("%Warning")
            || l.starts_with("- Verilator")
            || l.starts_with("- V e r i l a t i o n")
        {
            Some(Self::Verilator)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Simulator;

    #[test]
    fn detects_by_banner_or_message_form() {
        assert_eq!(
            Simulator::detect("# vsim -c work.top"),
            Some(Simulator::Questa)
        );
        assert_eq!(
            Simulator::detect("# ** Error: (vlog-1) x"),
            Some(Simulator::Questa)
        );
        assert_eq!(
            Simulator::detect("Error-[XYZ] invented message"),
            Some(Simulator::Vcs)
        );
        assert_eq!(
            Simulator::detect("%Warning-WIDTH: a.sv:1:2: x"),
            Some(Simulator::Verilator)
        );
        assert_eq!(Simulator::detect("UVM_INFO @ 0: r [X] y"), None);
    }
}
