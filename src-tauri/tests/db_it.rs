//! Database blocks, driven through the runner the way a project would.
//!
//! The unit tests in `db` cover the rules against the module directly. These
//! run the same work as blocks, which is where a different class of mistake
//! shows: a parameter that never reaches the statement, a variable that is
//! written but not readable by the next block, or a result that comes back in
//! a shape the following block cannot use.
// These tests share one scratch directory, so a std Mutex serialises them. The
// guard is deliberately held across the awaits inside each test: that is what
// stops a second test from entering the directory mid-run. An async-aware lock
// would let them interleave, which is the bug this guard exists to prevent.
#![allow(clippy::await_holding_lock)]

use serde_json::{json, Value};
use shardx_launcher_lib::automation::{Block, Branch, Project, RunSettings};
use shardx_launcher_lib::runner::StepOutcome;
use shardx_launcher_lib::{runner, store};
use std::collections::HashMap;

fn block(id: &str, kind: &str, params: Value) -> Block {
    Block {
        id: id.into(),
        kind: kind.into(),
        label: String::new(),
        params,
        enabled: true,
        x: 0.0,
        y: 0.0,
        on_done: Branch::Next,
        secrets: Vec::new(),
        on_fail: Branch::Stop,
    }
}

fn project(blocks: Vec<Block>) -> Project {
    Project {
        id: "p-db".into(),
        name: "DB".into(),
        notes: String::new(),
        blocks,
        run: RunSettings::default(),
        created_at: 0,
        updated_at: 0,
    }
}

fn scratch() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
    let guard = store::config_root_test_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("a scratch config root");
    store::set_config_root(Some(dir.path().to_path_buf()));
    (guard, dir)
}

/// The everyday shape: set up a table, write a row built from a variable,
/// read it back, and branch on what came out.
#[tokio::test]
async fn a_project_writes_rows_and_reads_them_back() {
    let (_lock, _dir) = scratch();

    let p = project(vec![
        block(
            "create",
            "dbExecute",
            json!({
                "database": "work.db",
                "sql": "create table if not exists seen (name text, done integer)",
            }),
        ),
        block(
            "insert",
            "dbExecute",
            json!({
                "database": "work.db",
                "sql": "insert into seen (name, done) values (?, ?)",
                "params": "[\"{{who}}\", 0]",
                "into": "changed",
            }),
        ),
        block(
            "read",
            "dbQuery",
            json!({
                "database": "work.db",
                "sql": "select name from seen where done = ?",
                "params": "[0]",
                "into": "rows",
                "countInto": "found",
                "firstColumn": "name",
                "firstInto": "next",
                "minRows": 1,
            }),
        ),
    ]);

    let seed = HashMap::from([("who".to_string(), "alice".to_string())]);
    let report = runner::run(&p, "no-browser-needed", seed)
        .await
        .expect("a database-only project needs no browser");

    assert!(report.ok, "the run should have succeeded: {report:?}");
    assert_eq!(
        report.variables.get("changed").map(String::as_str),
        Some("1")
    );
    assert_eq!(report.variables.get("found").map(String::as_str), Some("1"));
    // The value a following block would branch on, as a bare string rather
    // than a JSON-quoted one.
    assert_eq!(
        report.variables.get("next").map(String::as_str),
        Some("alice")
    );

    let rows: Vec<Value> =
        serde_json::from_str(report.variables.get("rows").expect("rows")).expect("rows are JSON");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], json!("alice"));
}

/// The property the binding exists for, end to end: a page-scraped value that
/// happens to be SQL is data, not a second statement.
#[tokio::test]
async fn a_scraped_value_cannot_become_sql() {
    let (_lock, _dir) = scratch();

    let p = project(vec![
        block(
            "create",
            "dbExecute",
            json!({ "database": "work.db", "sql": "create table t (name text)" }),
        ),
        block(
            "insert",
            "dbExecute",
            json!({
                "database": "work.db",
                "sql": "insert into t (name) values (?)",
                "params": "[\"{{scraped}}\"]",
            }),
        ),
        block(
            "count",
            "dbQuery",
            json!({
                "database": "work.db",
                "sql": "select count(*) as n from t",
                "into": "rows",
                "firstColumn": "n",
                "firstInto": "n",
            }),
        ),
    ]);

    let seed = HashMap::from([("scraped".to_string(), "'); drop table t; --".to_string())]);
    let report = runner::run(&p, "no-browser-needed", seed)
        .await
        .expect("the run should finish");

    assert!(report.ok, "the run should have succeeded: {report:?}");
    // The table still exists and holds the hostile string as an ordinary row.
    assert_eq!(report.variables.get("n").map(String::as_str), Some("1"));
}

/// A project that asks for rows it needs and does not get them should fail,
/// not carry on with an empty variable.
#[tokio::test]
async fn a_query_that_finds_nothing_can_fail_the_run() {
    let (_lock, _dir) = scratch();

    let p = project(vec![
        block(
            "create",
            "dbExecute",
            json!({ "database": "work.db", "sql": "create table t (name text)" }),
        ),
        block(
            "read",
            "dbQuery",
            json!({
                "database": "work.db",
                "sql": "select name from t",
                "into": "rows",
                "minRows": 1,
            }),
        ),
    ]);

    let report = runner::run(&p, "no-browser-needed", HashMap::new())
        .await
        .expect("the run should finish, reporting the failure");

    assert!(
        !report.ok,
        "an unmet minRows should fail the run: {report:?}"
    );
    let failed = report
        .steps
        .iter()
        .find(|s| s.block_id == "read")
        .expect("the query step");
    let error = failed.error.clone().unwrap_or_default();
    assert!(
        error.contains("fewer than"),
        "the error should say what was missing: {error}"
    );
}

/// Databases persist between runs, which is what makes them useful for
/// resuming work -- and worth proving rather than assuming.
#[tokio::test]
async fn rows_survive_into_a_later_run() {
    let (_lock, _dir) = scratch();

    let first = project(vec![
        block(
            "create",
            "dbExecute",
            json!({ "database": "work.db", "sql": "create table t (name text)" }),
        ),
        block(
            "insert",
            "dbExecute",
            json!({
                "database": "work.db",
                "sql": "insert into t (name) values (?)",
                "params": "[\"kept\"]",
            }),
        ),
    ]);
    let report = runner::run(&first, "no-browser-needed", HashMap::new())
        .await
        .expect("the first run");
    assert!(report.ok, "the first run should have succeeded: {report:?}");

    let second = project(vec![block(
        "read",
        "dbQuery",
        json!({
            "database": "work.db",
            "sql": "select name from t",
            "into": "rows",
            "firstColumn": "name",
            "firstInto": "name",
            "minRows": 1,
        }),
    )]);
    let report = runner::run(&second, "no-browser-needed", HashMap::new())
        .await
        .expect("the second run");

    assert!(
        report.ok,
        "the second run should have succeeded: {report:?}"
    );
    assert_eq!(
        report.variables.get("name").map(String::as_str),
        Some("kept")
    );
}

/// A project naming a database outside the workspace is refused at the block,
/// not somewhere deeper where the path has already been opened.
#[tokio::test]
async fn a_project_cannot_open_a_database_outside_the_workspace() {
    let (_lock, _dir) = scratch();

    let p = project(vec![block(
        "escape",
        "dbExecute",
        json!({
            "database": "../../escaped.db",
            "sql": "create table t (a int)",
        }),
    )]);

    let report = runner::run(&p, "no-browser-needed", HashMap::new())
        .await
        .expect("the run should finish, reporting the failure");

    assert!(!report.ok, "the run should have failed: {report:?}");
    let error = report.steps[0].error.clone().unwrap_or_default();
    assert!(error.contains(".."), "the error should say why: {error}");
}

/// A scraped value containing a quote must not restructure the params array.
///
/// `params` is written by hand in the editor, so it arrives as a JSON *string*
/// and the variables inside it are substituted before the array is parsed. That
/// ordering is the risk: a value like `alice"` would close its own string, and
/// `alice", "extra` would add an element the project never wrote. SQL injection
/// is already off the table because the values are bound, but a params array
/// that silently grows an element binds the wrong value to the wrong column,
/// which is its own corruption.
#[tokio::test]
async fn a_quote_in_a_value_cannot_add_a_parameter() {
    let (_guard, _dir) = scratch();

    let p = project(vec![
        block(
            "make",
            "dbExecute",
            json!({ "database": "quotes", "sql": "CREATE TABLE t (a TEXT, b TEXT)" }),
        ),
        block(
            "name",
            "setVariable",
            json!({ "name": "who", "value": "alice\", \"injected" }),
        ),
        block(
            "insert",
            "dbExecute",
            json!({
                "database": "quotes",
                "sql": "INSERT INTO t (a, b) VALUES (?, ?)",
                "params": "[\"{{who}}\", \"real\"]",
            }),
        ),
        block(
            "read",
            "dbQuery",
            json!({
                "database": "quotes",
                "sql": "SELECT a, b FROM t",
                "into": "rows",
            }),
        ),
    ]);

    let report = runner::run(&p, "db-profile", HashMap::new())
        .await
        .expect("the run should start");

    assert!(
        report.ok,
        "the quote belongs inside the value, so the run should succeed: {:?}",
        report
            .steps
            .iter()
            .find(|s| matches!(s.outcome, StepOutcome::Failed)),
    );

    let rows: Vec<Value> =
        serde_json::from_str(&report.variables["rows"]).expect("rows should be JSON");
    assert_eq!(rows.len(), 1, "exactly one row should have been inserted");
    assert_eq!(
        rows[0]["b"], "real",
        "the second column must still hold the value the project wrote, not one \
         shifted in by a quote in the first: {rows:?}"
    );
    assert_eq!(
        rows[0]["a"], "alice\", \"injected",
        "the quote and everything after it belong inside the value: {rows:?}"
    );
}

/// SQL built out of a value the project did not choose is refused.
///
/// `params` already exists and binds properly, so this is a rewrite rather
/// than a restriction — and the refusal says so, because an operator who
/// cannot see the alternative will reach for a worse workaround.
///
/// The outside value here arrives from a file, which is the same class of
/// source as a scraped page: the project did not pick the characters.
#[tokio::test]
async fn sql_built_from_an_outside_value_is_refused() {
    let (_lock, _dir) = scratch();

    let p = project(vec![
        block(
            "create",
            "dbExecute",
            json!({ "database": "work.db", "sql": "create table t (name text)" }),
        ),
        block(
            "seed",
            "dbExecute",
            json!({
                "database": "work.db",
                "sql": "insert into t (name) values (?)",
                "params": ["alice"],
            }),
        ),
        block(
            "plant",
            "writeFile",
            json!({ "path": "name.txt", "contents": "alice'; drop table t; --" }),
        ),
        block(
            "read",
            "readFile",
            json!({ "path": "name.txt", "into": "who" }),
        ),
        // The operator means "look up that name", but the name decides the
        // statement.
        block(
            "lookup",
            "dbQuery",
            json!({
                "database": "work.db",
                "sql": "select name from t where name = '{{who}}'",
                "into": "rows",
            }),
        ),
    ]);

    let report = runner::run(&p, "no-profile-needed", HashMap::new())
        .await
        .expect("a database-only project needs no browser");

    let step = report
        .steps
        .iter()
        .find(|s| s.block_id == "lookup")
        .expect("the query step should be in the report");
    let error = step.error.as_deref().unwrap_or_default();
    assert!(
        error.contains("who") && error.contains("outside the project"),
        "the refusal should name the variable and why: {error:?}"
    );
    assert!(
        error.contains("params"),
        "the refusal should point at binding as the way to do this: {error:?}"
    );
    assert!(
        !report.ok,
        "a refused step should fail the run rather than pass quietly"
    );
}

/// And the safe path works: the same outside value, bound as a parameter,
/// queries exactly what it says without the statement changing shape.
#[tokio::test]
async fn an_outside_value_still_queries_when_it_is_bound() {
    let (_lock, _dir) = scratch();

    let p = project(vec![
        block(
            "create",
            "dbExecute",
            json!({ "database": "work.db", "sql": "create table t (name text)" }),
        ),
        block(
            "seed",
            "dbExecute",
            json!({
                "database": "work.db",
                "sql": "insert into t (name) values (?)",
                "params": ["o'brien"],
            }),
        ),
        block(
            "plant",
            "writeFile",
            // A name containing a quote: harmless bound, syntax if spliced.
            json!({ "path": "name.txt", "contents": "o'brien" }),
        ),
        block(
            "read",
            "readFile",
            json!({ "path": "name.txt", "into": "who" }),
        ),
        block(
            "lookup",
            "dbQuery",
            json!({
                "database": "work.db",
                "sql": "select name from t where name = ?",
                "params": ["{{who}}"],
                "into": "rows",
                "countInto": "found",
            }),
        ),
    ]);

    let report = runner::run(&p, "no-profile-needed", HashMap::new())
        .await
        .expect("a database-only project needs no browser");

    assert!(
        report.ok,
        "binding the value is the supported way to do this: {:?}",
        report
            .steps
            .iter()
            .find(|s| matches!(s.outcome, StepOutcome::Failed)),
    );
    assert_eq!(
        report.variables.get("found").map(String::as_str),
        Some("1"),
        "the bound value should have matched the row it names: {:?}",
        report.variables
    );
}
