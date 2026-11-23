//! Schema identifiers. Until the 0.1 contracts are frozen every schema carries a development version
//! (`1.0-dev.N`); servers accept only their own development version.

/// Development revision shared by all wire schemas in this build.
pub const DEV_REVISION: u32 = 3;

macro_rules! schema_ids {
    ($($(#[$doc:meta])* $name:ident => $base:literal;)*) => {
        $( $(#[$doc])* pub const $name: &str = concat!($base, "/1.0-dev.3"); )*
        /// Every schema identifier, for capabilities and generation.
        pub const ALL: &[&str] = &[$($name),*];
    };
}

schema_ids! {
    /// Ingest records (regressions, manifests, attempts).
    INGEST => "dviscope.ingest";
    /// Evidence envelopes.
    EVIDENCE => "dviscope.evidence";
    /// Manifest chunks and operations.
    MANIFEST => "dviscope.manifest";
    /// Delivery journal entries.
    JOURNAL => "dviscope.journal";
}

#[cfg(test)]
mod tests {
    #[test]
    fn dev_revision_matches_ids() {
        for id in super::ALL {
            assert!(
                id.ends_with(&format!("/1.0-dev.{}", super::DEV_REVISION)),
                "{id}"
            );
        }
    }
}
