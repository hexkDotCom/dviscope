//! The acceptance manifest is well formed: unique IDs, known layers, stages 1-7, an oracle
//! for every case.

#[test]
fn acceptance_manifest_is_well_formed() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/acceptance/manifest.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: toml::Table = toml::from_str(&text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.get("schema").and_then(toml::Value::as_str),
        Some("dviscope.acceptance/1")
    );
    let cases = doc
        .get("case")
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("no cases"));
    let mut ids = std::collections::HashSet::new();
    for c in cases {
        let id = c
            .get("id")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("case without id"));
        assert!(ids.insert(id.to_string()), "duplicate case {id}");
        let stage = c
            .get("stage")
            .and_then(toml::Value::as_integer)
            .unwrap_or(0);
        assert!((1..=7).contains(&stage), "{id}: stage {stage}");
        let oracle = c.get("oracle").and_then(toml::Value::as_str).unwrap_or("");
        assert!(oracle.len() > 20, "{id}: oracle too short");
        let status = c.get("status").and_then(toml::Value::as_str).unwrap_or("");
        assert!(
            matches!(status, "planned" | "implemented"),
            "{id}: status {status}"
        );
        if status == "implemented" {
            // An implemented case names the test that proves it, and that file exists.
            let t = c.get("test").and_then(toml::Value::as_str).unwrap_or("");
            let file = t.split([':', ',', ' ']).next().unwrap_or("");
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            assert!(
                !file.is_empty() && root.join(file).is_file(),
                "{id}: implemented without an existing test ({t})"
            );
        }
    }
    assert!(
        ids.len() >= 26,
        "expected every B.13 case, found {}",
        ids.len()
    );
}
