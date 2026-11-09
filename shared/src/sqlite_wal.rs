//! A guard for RUSTSEC-2026-0459 (CVE-2026-119375): SQLite before 3.54.0 can
//! return uninitialized page-cache memory when a database is opened with a
//! `-wal` whose page size differs from the database's. A profile's databases
//! may come from another device's snapshot, so such a pair is refused before
//! SQLite opens it.
// shortcut: needed while the bundled SQLite is older than 3.54.0; drop it once
// `libsqlite3-sys` >= 0.39 builds (`sqlx` 0.9 still caps it below 0.38).

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::Path;

/// Refuses `db_path` when its `-wal` carries a valid header whose page size
/// is not the database header's. A missing or short file has nothing to
/// disagree with: SQLite ignores a WAL without a valid header, and reads
/// page 1 from the WAL when the database file is still empty.
pub fn check_wal(db_path: &Path) -> Result<()> {
    let mut wal_path = db_path.as_os_str().to_owned();
    wal_path.push("-wal");
    let wal = head(Path::new(&wal_path), 32)?;
    let db = head(db_path, 100)?;
    if wal.len() < 32 || db.len() < 100 || !matches!(be32(&wal[0..4]), 0x377f_0682 | 0x377f_0683) {
        return Ok(());
    }
    let wal_page = be32(&wal[8..12]);
    // The database header stores 65536 as 1.
    let db_page = match u16::from_be_bytes([db[16], db[17]]) {
        1 => 65_536,
        n => u32::from(n),
    };
    if wal_page != db_page {
        bail!(
            "{} has a -wal whose page size ({wal_page}) is not the database's ({db_page})",
            db_path.display()
        );
    }
    Ok(())
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Up to the first `n` bytes of `path`; empty when it does not exist.
fn head(path: &Path, n: u64) -> Result<Vec<u8>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    let mut buf = Vec::new();
    file.take(n)
        .read_to_end(&mut buf)
        .with_context(|| format!("read {}", path.display()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shardx-wal-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A database whose last row lives only in its `-wal`, copied while the
    /// writer is open so the pair is what a hard-killed browser leaves.
    fn wal_pair(dir: &Path) -> std::path::PathBuf {
        let src = dir.join("src");
        let writer = Connection::open(&src).unwrap();
        writer.pragma_update(None, "journal_mode", "WAL").unwrap();
        writer
            .pragma_update(None, "wal_autocheckpoint", 0i64)
            .unwrap();
        writer
            .execute_batch(
                "CREATE TABLE t(v); PRAGMA wal_checkpoint(TRUNCATE); INSERT INTO t VALUES ('wal');",
            )
            .unwrap();
        let db = dir.join("Cookies");
        std::fs::copy(&src, &db).unwrap();
        std::fs::copy(dir.join("src-wal"), dir.join("Cookies-wal")).unwrap();
        drop(writer);
        db
    }

    #[test]
    fn a_matching_pair_and_a_lone_database_pass() {
        let dir = tmp("ok");
        let db = wal_pair(&dir);
        check_wal(&db).unwrap();
        let rows: i64 = Connection::open(&db)
            .unwrap()
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the row in the -wal is read");
        std::fs::remove_file(dir.join("Cookies-wal")).ok();
        check_wal(&db).unwrap();
        check_wal(&dir.join("missing")).unwrap();
    }

    #[test]
    fn a_wal_with_another_page_size_is_refused() {
        let dir = tmp("bad");
        let db = wal_pair(&dir);
        let wal = dir.join("Cookies-wal");
        let mut bytes = std::fs::read(&wal).unwrap();
        bytes[8..12].copy_from_slice(&8192u32.to_be_bytes());
        std::fs::write(&wal, bytes).unwrap();
        let err = check_wal(&db).unwrap_err().to_string();
        assert!(err.contains("page size (8192)"), "{err}");
        // The profile database readers refuse it before SQLite opens it.
        let crypt = crate::oscrypt::LocalCrypt::with_key(vec![0x66; 16]);
        for err in [
            crate::cookies::read(&db, &crypt).unwrap_err(),
            crate::logins::read(&db, &crypt).unwrap_err(),
        ] {
            assert!(err.to_string().contains("page size (8192)"), "{err}");
        }
    }
}
