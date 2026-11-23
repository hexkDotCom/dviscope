//! A Verilator model with its own main at ingest. The slot's declaration
//! (`extra.tool.main = "model"`) and the evidence's profile must agree both ways; the
//! simulator recorded is Verilator with a meaningful exit code. Invented toy markers.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use dviscope_core::extract::{ExtractOptions, Extractor};
use dviscope_core::packs::{PackInput, compile, shipped};
use dviscope_model::wire::evidence::Evidence;
use serde_json::{Value, json};

const MODEL: &str = r#"
format: dviscope.rules/1.0
pack: toymodel
version: 1.0.0
tier: project
markers:
  - {id: begin, match: '^TOY MODEL BEGIN$'}
  - {id: end, match: '^TOY END$'}
verdicts:
  - {id: res, source: test_result, match: '^TOY RESULT PASS$', value: pass}
completion:
  model_main: {start: begin, trailer: [end]}
"#;

fn model_evidence() -> Evidence {
    let mut inputs = shipped::default_inputs();
    inputs.push(PackInput {
        name: "toymodel.yaml".into(),
        text: MODEL.into(),
    });
    let p = compile(&inputs).unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("program.log");
    o.model_main = true;
    let mut x = Extractor::new(&p, o);
    x.push(b"TOY RESULT PASS\n");
    x.begin_console();
    x.push(b"TOY MODEL BEGIN\n- rtl/top.sv:3: Verilog $finish\nTOY END\n");
    x.finish()
}

fn declared(s: &str) -> Value {
    let mut v = slot(s);
    v["exec_inputs"]["extra"] = json!({"tool": {"main": "model"}});
    v
}

/// A report whose execution is the declared slot's.
fn model_report(r: &str, s: &str, a: &str, ev: &Evidence) -> Value {
    let mut v = report(r, s, a, 1, 1, ev, &[]);
    v["execution"]["extra"] = json!({"tool": {"main": "model"}});
    v
}

#[tokio::test]
async fn declaration_and_profile_agree_both_ways() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let mm = model_evidence();
    accept_pipeline(&t.pool, &mm).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(
        &app,
        &c,
        "r1",
        &[declared("m1"), declared("m2"), slot("p1"), declared("m3")],
    )
    .await;
    for (s, a) in [("m1", "a1"), ("m2", "a2"), ("p1", "a3"), ("m3", "a4")] {
        ok(ingest(&app, &c, &started("r1", s, a, 1, &[])).await);
    }
    // The declared slot with model evidence: accepted, passed, simulator Verilator.
    ok(ingest(&app, &c, &model_report("r1", "m1", "a1", &mm)).await);
    let sim: String = sqlx::query_scalar(
        "SELECT f.simulator FROM attempt_facts f JOIN attempts a ON a.id = f.attempt_id
          WHERE a.project_id = $1 AND a.attempt_ref = 'a1'",
    )
    .bind(pid)
    .fetch_one(&t.pool)
    .await
    .unwrap();
    assert_eq!(sim, "verilator");
    assert_eq!(state(&read(&app, pid, "r1").await, "m1")["state"], "passed");
    // The declared slot with ordinary evidence (a producer switching profile): refused.
    let e = ingest(&app, &c, &model_report("r1", "m2", "a2", &passing()))
        .await
        .err()
        .map(|e| format!("{e:?}"))
        .unwrap_or_default();
    assert!(e.contains("verilator-model-main"), "{e}");
    // An undeclared slot with model evidence: refused.
    let e = ingest(&app, &c, &report("r1", "p1", "a3", 1, 1, &mm, &[]))
        .await
        .err()
        .map(|e| format!("{e:?}"))
        .unwrap_or_default();
    assert!(e.contains("extra.tool.main"), "{e}");
    // Malformed segments: refused.
    let mut bad = mm.clone();
    if let Some(s) = bad.source.segments.as_mut() {
        s.reverse();
    }
    let e = ingest(&app, &c, &model_report("r1", "m2", "a2", &bad))
        .await
        .err()
        .map(|e| format!("{e:?}"))
        .unwrap_or_default();
    assert!(e.contains("segments"), "{e}");
    // An impossible verdict span (past the end): refused, never a pass.
    let mut bad = mm.clone();
    if let Some(sp) = bad.verdict_sources[0].span.as_mut() {
        sp.byte_start = dviscope_model::values::SafeU64::saturating(10_000);
        sp.byte_end = dviscope_model::values::SafeU64::saturating(0);
    }
    let e = ingest(&app, &c, &model_report("r1", "m2", "a2", &bad))
        .await
        .err()
        .map(|e| format!("{e:?}"))
        .unwrap_or_default();
    assert!(e.contains("span"), "{e}");
    // Recovery evidence of a declared slot (no log, the declared profile, no segments) is
    // accepted, and never a pass.
    let mut inputs = shipped::default_inputs();
    inputs.push(PackInput {
        name: "toymodel.yaml".into(),
        text: MODEL.into(),
    });
    let pl = compile(&inputs).unwrap();
    let mut o = ExtractOptions::simulation("program.log");
    o.model_main = true;
    let empty = Extractor::new(&pl, o).finish();
    assert!(empty.source.segments.is_none());
    ok(ingest(&app, &c, &model_report("r1", "m3", "a4", &empty)).await);
    assert_ne!(state(&read(&app, pid, "r1").await, "m3")["state"], "passed");
    // Build evidence never has segments.
    let mut b = build_report("b1", "pass");
    b["evidence"] = serde_json::to_value(&mm).unwrap();
    ok(ingest(&app, &c, &build_started("b1")).await);
    let e = ingest(&app, &c, &b)
        .await
        .err()
        .map(|e| format!("{e:?}"))
        .unwrap_or_default();
    assert!(e.contains("segments"), "{e}");
    t.drop().await;
}
