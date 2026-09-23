//! A small SQLite database a project may keep for itself.
//!
//! Runs need somewhere to remember things between passes and between runs:
//! which accounts have been handled, what an earlier step found, a queue of
//! work to take the next item from. Files cover the simple end of that, but
//! anything with more than one field per row turns into hand-rolled parsing,
//! and a run interrupted mid-append leaves a half-written line behind.
//!
//! The rules here are the same as `files`, for the same reason: a project is
//! data that arrives over the API, from an MCP client, or from a teammate's
//! export. So databases live in the automation workspace under a project-
//! supplied name that is resolved and contained exactly like a file path.
//!
//! Two limits are deliberate:
//!
//! Values are bound as parameters, never pasted into the statement. A project
//! that writes `select * from t where name = {{who}}` would otherwise be one
//! apostrophe away from a broken query and one semicolon away from a
//! different one -- and `{{who}}` is frequently a value the run just read off
//! a page, which is to say attacker-controlled input.
//!
//! One statement per block. `execute_batch` would let a single `query` block
//! carry `attach database 'C:\...'`, which is the workspace boundary undone
//! from inside SQL.

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::files;

/// Cap on rows returned into a variable. A `select` with no `where` against a
/// table a long-running project has been filling would otherwise pull an
/// unbounded result into memory and into the run report.
const MAX_ROWS: usize = 1_000;

/// Open a database inside the automation workspace.
///
/// The name is resolved through the same containment check as a file, so
/// `../../profiles/x.db` and `C:\Windows\...` are refused rather than opened.
fn open(name: &str) -> Result<Connection> {
    let path = files::resolve_for_db(name)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("the folder for {} could not be created", path.display()))?;
    }

    let conn = Connection::open(&path)
        .with_context(|| format!("the database {} could not be opened", path.display()))?;

    // A project's own statements must not be able to reach a second file.
    // Allowing zero attached databases makes `attach database 'C:\\...'` fail
    // outright, which is the workspace boundary holding from inside SQL too.
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0);

    Ok(conn)
}

/// Bind a project's parameters, which arrive as JSON, to SQLite values.
///
/// Numbers and booleans keep their type so `where id = ?` matches an integer
/// column; everything else goes in as text. Nested arrays and objects are
/// refused rather than silently stringified into something that will never
/// match a row.
fn bind(params: &[Value]) -> Result<Vec<SqlValue>> {
    params
        .iter()
        .map(|value| match value {
            Value::Null => Ok(SqlValue::Null),
            Value::Bool(b) => Ok(SqlValue::Integer(i64::from(*b))),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(SqlValue::Integer(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(SqlValue::Real(f))
                } else {
                    Err(anyhow!("a parameter number is out of range: {n}"))
                }
            }
            Value::String(s) => Ok(SqlValue::Text(s.clone())),
            other => Err(anyhow!(
                "a parameter must be a string, number, boolean or null, not {other}"
            )),
        })
        .collect()
}

/// Refuse a statement that carries more than one command.
///
/// rusqlite's `prepare` already ignores anything after the first statement,
/// which is the dangerous shape: a project reading `select 1; drop table t`
/// would appear to work while the second half was quietly dropped -- or, on a
/// different code path, quietly run.
fn single_statement(sql: &str) -> Result<()> {
    let trimmed = sql.trim().trim_end_matches(';');
    let mut in_single = false;
    let mut in_double = false;
    for ch in trimmed.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ';' if !in_single && !in_double => {
                bail!("a block runs one statement; remove the ';' and use a second block")
            }
            _ => {}
        }
    }
    Ok(())
}

/// Run a statement that returns no rows, reporting how many it changed.
pub fn execute(name: &str, sql: &str, params: &[Value]) -> Result<usize> {
    single_statement(sql)?;
    let conn = open(name)?;
    let bound = bind(params)?;
    let changed = conn
        .prepare(sql)
        .with_context(|| format!("the statement could not be prepared: {sql}"))?
        .execute(rusqlite::params_from_iter(bound))
        .with_context(|| format!("the statement failed: {sql}"))?;
    Ok(changed)
}

/// Run a query and return its rows as JSON objects.
pub fn query(name: &str, sql: &str, params: &[Value]) -> Result<Vec<Value>> {
    single_statement(sql)?;
    let conn = open(name)?;
    let bound = bind(params)?;

    let mut stmt = conn
        .prepare(sql)
        .with_context(|| format!("the query could not be prepared: {sql}"))?;

    let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();

    let mut rows = stmt
        .query(rusqlite::params_from_iter(bound))
        .with_context(|| format!("the query failed: {sql}"))?;

    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        if out.len() >= MAX_ROWS {
            bail!("the query returned more than {MAX_ROWS} rows; add a limit or a where clause");
        }
        let mut object = Map::new();
        for (i, column) in columns.iter().enumerate() {
            let value = match row.get_ref(i)? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(v) => json!(v),
                ValueRef::Real(v) => json!(v),
                ValueRef::Text(v) => json!(String::from_utf8_lossy(v).to_string()),
                // Blobs have no honest JSON form, and a project that stores
                // one is not reading it back through a variable.
                ValueRef::Blob(v) => json!(format!("<{} bytes>", v.len())),
            };
            object.insert(column.clone(), value);
        }
        out.push(Value::Object(object));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    fn scratch() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = store::config_root_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("a scratch config root");
        store::set_config_root(Some(dir.path().to_path_buf()));
        (guard, dir)
    }

    #[test]
    fn a_project_can_keep_rows_between_blocks() {
        let (_lock, _dir) = scratch();

        execute(
            "work.db",
            "create table seen (name text, done integer)",
            &[],
        )
        .unwrap();
        let changed = execute(
            "work.db",
            "insert into seen (name, done) values (?, ?)",
            &[json!("alice"), json!(1)],
        )
        .unwrap();
        assert_eq!(changed, 1, "the insert should have changed one row");

        let rows = query("work.db", "select name, done from seen", &[]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], json!("alice"));
        // Integers must come back as integers, or `done = 1` in a later query
        // would never match.
        assert_eq!(rows[0]["done"], json!(1));
    }

    /// The point of binding parameters: a value that is also SQL must be
    /// treated as a value.
    #[test]
    fn a_value_that_looks_like_sql_is_still_a_value() {
        let (_lock, _dir) = scratch();

        execute("work.db", "create table t (name text)", &[]).unwrap();
        execute("work.db", "insert into t (name) values (?)", &[json!("a")]).unwrap();
        execute(
            "work.db",
            "insert into t (name) values (?)",
            &[json!("'); drop table t; --")],
        )
        .unwrap();

        let rows = query("work.db", "select name from t order by name", &[]).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "the table should still be there with both rows"
        );
        assert_eq!(rows[1]["name"], json!("a"));
    }

    #[test]
    fn a_database_cannot_be_opened_outside_the_workspace() {
        let (_lock, _dir) = scratch();

        let err = execute("../escaped.db", "create table t (a int)", &[])
            .expect_err("a path climbing out of the workspace must be refused");
        assert!(
            err.to_string().contains(".."),
            "the error should say why: {err}"
        );

        let absolute = if cfg!(windows) {
            "C:/Windows/Temp/escaped.db"
        } else {
            "/tmp/escaped.db"
        };
        let err = execute(absolute, "create table t (a int)", &[])
            .expect_err("an absolute path must be refused");
        assert!(
            err.to_string().contains("relative"),
            "the error should say why: {err}"
        );
    }

    #[test]
    fn a_block_runs_one_statement_only() {
        let (_lock, _dir) = scratch();

        execute("work.db", "create table t (a int)", &[]).unwrap();
        let err = execute("work.db", "insert into t values (1); drop table t", &[])
            .expect_err("a second statement must be refused");
        assert!(
            err.to_string().contains("one statement"),
            "the error should say why: {err}"
        );

        // And the table it tried to drop is still there.
        let rows = query("work.db", "select a from t", &[]).unwrap();
        assert!(rows.is_empty(), "the refused insert should not have run");
    }

    /// A semicolon inside a string is part of the value, not a second
    /// statement -- rejecting it would make legitimate data unwritable.
    #[test]
    fn a_semicolon_inside_a_value_is_not_a_second_statement() {
        let (_lock, _dir) = scratch();

        execute("work.db", "create table t (note text)", &[]).unwrap();
        execute("work.db", "insert into t (note) values ('one; two')", &[])
            .expect("a semicolon inside a literal is part of the value");

        let rows = query("work.db", "select note from t", &[]).unwrap();
        assert_eq!(rows[0]["note"], json!("one; two"));
    }

    #[test]
    fn a_runaway_query_is_refused_rather_than_read_into_memory() {
        let (_lock, _dir) = scratch();

        execute("work.db", "create table t (a int)", &[]).unwrap();
        // A recursive CTE stands in for a table that grew past the cap.
        let err = query(
            "work.db",
            "with recursive n(x) as (select 1 union all select x + 1 from n where x < 5000) \
             select x from n",
            &[],
        )
        .expect_err("a result past the cap must be refused");
        assert!(
            err.to_string().contains("more than"),
            "the error should say why: {err}"
        );
    }

    /// The containment check guards the name a project passes. ATTACH would
    /// reach a second file without ever going through it, so the connection
    /// has to refuse that too.
    #[test]
    fn a_statement_cannot_attach_a_database_outside_the_workspace() {
        let (_lock, _dir) = scratch();

        let outside = if cfg!(windows) {
            "C:/Windows/Temp/attached.db"
        } else {
            "/tmp/attached.db"
        };
        let err = execute(
            "work.db",
            &format!("attach database '{outside}' as other"),
            &[],
        )
        .expect_err("attaching a second database must fail");
        let text = err.to_string();
        assert!(
            text.contains("too many attached") || text.contains("attach"),
            "the error should be about attaching: {err}"
        );
    }

    #[test]
    fn a_missing_table_fails_naming_the_statement() {
        let (_lock, _dir) = scratch();

        let err = query("work.db", "select * from nope", &[])
            .expect_err("a query against a missing table must fail");
        assert!(
            err.to_string().contains("nope"),
            "the error should name the statement: {err}"
        );
    }

    #[test]
    fn a_parameter_must_be_a_simple_value() {
        let (_lock, _dir) = scratch();

        execute("work.db", "create table t (a text)", &[]).unwrap();
        let err = execute(
            "work.db",
            "insert into t (a) values (?)",
            &[json!({ "nested": true })],
        )
        .expect_err("an object parameter must be refused");
        assert!(
            err.to_string().contains("must be a string"),
            "the error should say why: {err}"
        );
    }

    // `VACUUM INTO` writes a whole database to a path of the statement's
    // choosing without attaching anything, so it is worth proving that the
    // zero-attachment limit stops it too rather than assuming ATTACH was the
    // only way out. SQLite counts the destination against that limit.
    #[test]
    fn a_statement_cannot_write_a_database_outside_the_workspace() {
        let escape = std::env::temp_dir().join("shardx-vacuum-escape.db");
        let _ = std::fs::remove_file(&escape);

        let sql = format!(
            "vacuum into '{}'",
            escape.display().to_string().replace('\\', "/")
        );
        execute("probe.db", &sql, &[])
            .expect_err("a statement that writes outside the workspace must be refused");

        assert!(
            !escape.exists(),
            "refusing it has to mean the file was never written: {}",
            escape.display()
        );
        let _ = std::fs::remove_file(&escape);
    }

}
