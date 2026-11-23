//! A restore whose `pg_restore` dies part-way commits nothing (the
//! restore uses a wrapper directory of client tools).
//! Invented records only; Unix (the wrapper is a shell script).

#![cfg(unix)]

mod common;

use common::*;
use time::OffsetDateTime;

fn real_bin_dir() -> Option<std::path::PathBuf> {
    if let Some(d) = std::env::var_os("DVISCOPE_PG_BIN_DIR").filter(|d| !d.is_empty()) {
        return Some(std::path::PathBuf::from(d));
    }
    let o = std::process::Command::new("sh")
        .args(["-c", "command -v pg_restore"])
        .output()
        .ok()?;
    let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
    std::path::Path::new(&p)
        .parent()
        .map(std::path::Path::to_path_buf)
}

/// pg_restore streams the first part of a valid script and fails: psql never receives
/// COMMIT, so the target keeps its own data and no safe state is half-applied.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_truncated_restore_commits_nothing() {
    let Some(real) = real_bin_dir() else {
        eprintln!("skipped: no pg_restore");
        return;
    };
    let Some(a) = TestDb::new().await else { return };
    let app = a.app();
    let _pid = project(&a.pool).await;
    let (c, _) = collector(&a.pool).await;
    accept_pipeline(&a.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    finish(&app, &c, "r1").await;
    let d = std::env::temp_dir().join(format!("dviscope-trunc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let archive = d.join("a.dump");
    if let Err(e) =
        dviscope_server::backup::backup(&a.pool, &a.url(), &archive, OffsetDateTime::now_utc())
            .await
    {
        // A server before 17 with newer client tools on PATH: refused (documented).
        assert!(
            format!("{e:#}").contains("cannot back up PostgreSQL"),
            "{e:#}"
        );
        let _ = std::fs::remove_dir_all(&d);
        a.drop().await;
        return;
    }

    // The wrapper: the real version and psql; the script cut after its first statements.
    let bin = d.join("bin");
    std::fs::create_dir_all(&bin).ok();
    std::os::unix::fs::symlink(real.join("psql"), bin.join("psql")).ok();
    std::os::unix::fs::symlink(real.join("pg_dump"), bin.join("pg_dump")).ok();
    let wrapper = format!(
        "#!/bin/sh\nif [ \"$1\" = --version ]; then exec '{r}/pg_restore' --version; fi\n\
         '{r}/pg_restore' \"$@\" | awk '{{print}} /;$/ {{n++}} n >= 60 {{exit}}'\nexit 1\n",
        r = real.display()
    );
    std::fs::write(bin.join("pg_restore"), wrapper).ok();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            bin.join("pg_restore"),
            std::fs::Permissions::from_mode(0o755),
        )
        .ok();
    }

    let Some(b) = TestDb::new().await else { return };
    dviscope_server::admin::create_project(&b.pool, "kept", "strict")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let shape = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
              WHERE n.nspname = 'public'",
        )
        .fetch_one(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
    };
    let before = shape().await;
    // The script is cut after whole statements (the first ones drop constraints): valid SQL
    // up to the cut, so only the missing COMMIT keeps it from landing.
    let r = dviscope_server::backup::restore_in(&b.url(), &archive, Some(&bin)).await;
    assert!(r.is_err(), "{r:?}");
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM projects ORDER BY name")
        .fetch_all(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        names,
        ["kept"],
        "the target's own data, nothing of the archive"
    );
    assert!(
        !dviscope_server::backup::maintenance_on(&b.pool)
            .await
            .unwrap_or(true),
        "no half-applied safe state"
    );
    let tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_tables WHERE schemaname = current_schema()")
            .fetch_one(&b.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    assert!(tables > 40, "no table was dropped: {tables}");
    assert_eq!(
        shape().await,
        before,
        "no statement of the cut script stayed"
    );
    let _ = std::fs::remove_dir_all(&d);
    b.drop().await;
    a.drop().await;
}
