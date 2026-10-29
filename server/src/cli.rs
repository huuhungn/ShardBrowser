//! Command line: with no arguments the binary runs the server; the offline
//! operator commands from ADR 0001 Option A run only while it is stopped.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use anyhow::Context;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::{audit, auth, bootstrap, db, identity, restore, util};

pub const USAGE: &str = "usage:
  shardx-team-server
      run the server
  shardx-team-server identity init
      create the epoch-0 identity record (server stopped)
  shardx-team-server identity show
      verify the identity record against the database mirror
  shardx-team-server restore status
      print the restore class (ADR 0002 D-1 K1-K12) and its plan row
  shardx-team-server restore export-heads --backup <db> --out <dir>
      write one transition request per tenant a restore of <db> must cover
  shardx-team-server restore prepare --backup <db> --txn <hex>
      build the candidate, its transition artifacts and the manifest
  shardx-team-server restore commit [--retire]
      finish a prepared restore from its current class
  shardx-team-server restore abort [--orphans [--delete-archives]]
      drop a restore whose authority is still the previous epoch; --orphans
      keeps the pre-restore archives unless --delete-archives is given
  shardx-team-server restore withdraw-transitions --tenant <id>
      remove a tenant's staged transition for the next restore epoch
  shardx-team-server tenant create --slug <slug> --owner-username <name> [--password-stdin]
      create a tenant and its owner account; the password is prompted for,
      or read from stdin with --password-stdin, never taken from argv or env
  shardx-team-server tenant confirm-first-device --tenant <slug> --device <id>
      show the pending first device's key IDs and record the operator's match
      (both IDs are read from stdin, as shown on the client)
  shardx-team-server tenant cancel-first-device --tenant <slug>
      close a confirmed first device that will not be approved; this tenant
      cannot bootstrap again
  shardx-team-server tenant first-device-status --tenant <slug>
      read the first-device confirmation back without changing anything";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Serve,
    IdentityInit,
    IdentityShow,
    RestoreStatus,
    RestoreExportHeads {
        backup: String,
        out: String,
    },
    RestorePrepare {
        backup: String,
        txn: [u8; 16],
    },
    RestoreCommit {
        retire: bool,
    },
    RestoreAbort {
        orphans: bool,
        delete_archives: bool,
    },
    RestoreWithdrawTransitions {
        tenant: [u8; 16],
    },
    TenantCreate {
        slug: String,
        owner_username: String,
        password_stdin: bool,
    },
    ConfirmFirstDevice {
        slug: String,
        device_id: [u8; 16],
    },
    CancelFirstDevice {
        slug: String,
    },
    FirstDeviceStatus {
        slug: String,
    },
}

/// Parse the arguments after the program name. Errors never echo an
/// argument: a mistyped one may be a password.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => Ok(Command::Serve),
        ["identity", "init"] => Ok(Command::IdentityInit),
        ["identity", "show"] => Ok(Command::IdentityShow),
        ["restore", "status"] => Ok(Command::RestoreStatus),
        ["restore", "export-heads", "--backup", backup, "--out", out] => {
            Ok(Command::RestoreExportHeads {
                backup: backup.to_string(),
                out: out.to_string(),
            })
        }
        ["restore", "prepare", "--backup", backup, "--txn", txn] => Ok(Command::RestorePrepare {
            backup: backup.to_string(),
            txn: bootstrap::parse_device_id(txn).ok_or("--txn must be 32 hex digits")?,
        }),
        ["restore", "commit"] => Ok(Command::RestoreCommit { retire: false }),
        ["restore", "commit", "--retire"] => Ok(Command::RestoreCommit { retire: true }),
        ["restore", "abort"] => Ok(Command::RestoreAbort {
            orphans: false,
            delete_archives: false,
        }),
        ["restore", "abort", "--orphans"] => Ok(Command::RestoreAbort {
            orphans: true,
            delete_archives: false,
        }),
        ["restore", "abort", "--orphans", "--delete-archives"] => Ok(Command::RestoreAbort {
            orphans: true,
            delete_archives: true,
        }),
        ["restore", "withdraw-transitions", "--tenant", tenant] => {
            Ok(Command::RestoreWithdrawTransitions {
                tenant: bootstrap::parse_device_id(tenant)
                    .ok_or("--tenant must be 32 hex digits")?,
            })
        }
        ["tenant", "create", rest @ ..] => parse_tenant_create(rest),
        ["tenant", "confirm-first-device", "--tenant", slug, "--device", device] => {
            Ok(Command::ConfirmFirstDevice {
                slug: slug.to_string(),
                device_id: bootstrap::parse_device_id(device)
                    .ok_or("--device must be 32 hex digits")?,
            })
        }
        ["tenant", "cancel-first-device", "--tenant", slug] => Ok(Command::CancelFirstDevice {
            slug: slug.to_string(),
        }),
        ["tenant", "first-device-status", "--tenant", slug] => Ok(Command::FirstDeviceStatus {
            slug: slug.to_string(),
        }),
        _ => Err("unrecognized command".into()),
    }
}

fn parse_tenant_create(rest: &[&str]) -> Result<Command, String> {
    let (mut slug, mut owner, mut password_stdin) = (None, None, false);
    let mut it = rest.iter().enumerate();
    while let Some((i, arg)) = it.next() {
        let mut value = || match it.next() {
            Some((_, v)) if !v.starts_with("--") => Ok(v.to_string()),
            _ => Err(format!("argument {} needs a value", i + 3)),
        };
        match *arg {
            "--slug" if slug.is_none() => slug = Some(value()?),
            "--owner-username" if owner.is_none() => owner = Some(value()?),
            "--password-stdin" if !password_stdin => password_stdin = true,
            _ => return Err(format!("unrecognized argument {}", i + 3)),
        }
    }
    Ok(Command::TenantCreate {
        slug: slug.ok_or("--slug is required")?,
        owner_username: owner.ok_or("--owner-username is required")?,
        password_stdin,
    })
}

/// Take the exclusive lock on `<data_dir>/shardx.lock` for the life of the
/// returned handle. The server and every command hold it, so an offline
/// command can never run beside a live server.
pub fn lock_data_dir(data_dir: &str) -> anyhow::Result<File> {
    std::fs::create_dir_all(data_dir)?;
    let path = Path::new(data_dir).join("shardx.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => anyhow::bail!(
            "another instance holds the data directory lock {} (the server is running?); \
             stop it first",
            path.display()
        ),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}

/// Run an offline command under the data directory lock.
pub async fn run(command: Command) -> anyhow::Result<()> {
    let cfg = Config::from_env();
    let _lock = lock_data_dir(&cfg.data_dir)?;
    match command {
        Command::Serve => unreachable!("the server is started by main"),
        Command::IdentityInit => identity::init(&cfg).await,
        Command::IdentityShow => {
            anyhow::ensure!(identity::show(&cfg).await?, "the identity does not verify");
            Ok(())
        }
        Command::RestoreStatus => restore::status(&cfg).await,
        Command::RestoreExportHeads { backup, out } => {
            restore::export_heads(&cfg, Path::new(&backup), Path::new(&out)).await
        }
        Command::RestorePrepare { backup, txn } => {
            restore::prepare(&cfg, Path::new(&backup), txn).await
        }
        Command::RestoreCommit { retire } => restore::commit(&cfg, retire).await,
        Command::RestoreAbort {
            orphans,
            delete_archives,
        } => restore::abort(&cfg, orphans, delete_archives).await,
        Command::RestoreWithdrawTransitions { tenant } => {
            restore::withdraw_transitions(&cfg, tenant).await
        }
        Command::TenantCreate {
            slug,
            owner_username,
            password_stdin,
        } => tenant_create(&cfg, &slug, &owner_username, password_stdin).await,
        Command::ConfirmFirstDevice { slug, device_id } => {
            bootstrap::confirm(&cfg, &slug, &device_id).await
        }
        Command::CancelFirstDevice { slug } => bootstrap::cancel(&cfg, &slug).await,
        Command::FirstDeviceStatus { slug } => bootstrap::status(&cfg, &slug).await,
    }
}

/// Login names a tenant by slug (plan L1122), so keep it URL- and shell-safe.
fn valid_slug(slug: &str) -> bool {
    (1..=63).contains(&slug.len())
        && !slug.starts_with('-')
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// v1 bounds usernames only by non-emptiness; this is the bound for v2 owners.
const MAX_USERNAME_CHARS: usize = 64;

/// Stored exactly as given, so reject what would make two names look alike
/// or break a log line.
fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_USERNAME_CHARS
        && name.trim() == name
        && !name.chars().any(char::is_control)
}

/// `tenant create` (ADR 0001 Option A, command 3). The caller holds the lock.
async fn tenant_create(
    cfg: &Config,
    slug: &str,
    owner_username: &str,
    password_stdin: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        valid_slug(slug),
        "--slug must be 1-63 characters of a-z, 0-9 and '-', not starting with '-'"
    );
    anyhow::ensure!(
        valid_username(owner_username),
        "--owner-username must be 1-{MAX_USERNAME_CHARS} characters with no control \
         characters and no leading or trailing whitespace"
    );

    // Verify through a read-only open first, so a refusal creates nothing:
    // no database file, no blob directory, no migration.
    let mirror = identity::read_mirror_read_only(cfg).await?;
    let verified = identity::authority(cfg, mirror.as_ref()).map_err(|r| {
        anyhow::anyhow!(
            "refusing: the server identity does not verify ({}: {}); run `identity show`",
            r.code.as_str(),
            r.detail
        )
    })?;
    let pool = db::init_pool(cfg).await?;

    let password = read_password(password_stdin).await?;
    anyhow::ensure!(
        !db::is_weak_password(&password),
        "refusing a weak owner password: use at least 8 characters and not a well-known \
         placeholder"
    );
    let pw_hash = auth::hash_password(&password).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    drop(password);

    let tenant_id = uuid::Uuid::new_v4().into_bytes();
    let account_id = uuid::Uuid::new_v4().into_bytes();
    let now = util::now_rfc3339();

    // One transaction: the audit row commits with the tenant or not at all.
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at) \
         VALUES (?, ?, 'active', NULL, ?)",
    )
    .bind(tenant_id.as_slice())
    .bind(slug)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .context("inserting the tenant")?;
    sqlx::query(
        "INSERT INTO v2_accounts \
         (id, tenant_id, username, pw_hash, legacy_user_id, token_version, status, created_at) \
         VALUES (?, ?, ?, ?, NULL, 0, 'active', ?)",
    )
    .bind(account_id.as_slice())
    .bind(tenant_id.as_slice())
    .bind(owner_username)
    .bind(&pw_hash)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .context("inserting the owner account")?;
    sqlx::query(
        "INSERT INTO v2_tenant_memberships (tenant_id, account_id, role, status, created_at) \
         VALUES (?, ?, 'owner', 'active', ?)",
    )
    .bind(tenant_id.as_slice())
    .bind(account_id.as_slice())
    .bind(&now)
    .execute(&mut *tx)
    .await
    .context("inserting the owner membership")?;
    // ADR 0001 R1: the tenant's one first-device opportunity starts here, and
    // only here; it is never inferred from empty tables later.
    sqlx::query(
        "INSERT INTO v2_bootstrap_guards \
         (server_instance_id, tenant_id, state, recovery_reason, updated_at) \
         VALUES (?, ?, 'unused', NULL, ?)",
    )
    .bind(verified.server_instance_id.as_slice())
    .bind(tenant_id.as_slice())
    .bind(&now)
    .execute(&mut *tx)
    .await
    .context("inserting the bootstrap guard")?;
    audit::insert_offline(
        &mut tx,
        &tenant_id,
        "tenant.create",
        "tenant",
        &tenant_id,
        &uuid::Uuid::new_v4().into_bytes(),
    )
    .await?;
    tx.commit().await?;
    pool.close().await;

    println!("tenant_id={}", identity::hex(&tenant_id));
    Ok(())
}

/// Read the owner password from stdin (`--password-stdin`) or a hidden
/// prompt. Refuses rather than blocks when there is no terminal to prompt on.
///
/// Every buffer that holds the password is zeroed when dropped.
// shortcut: copies std keeps out of reach (stdin's internal buffer, and old
// allocations if a line outgrows the reserved capacity) are not zeroed;
// fixing that needs a raw terminal reader.
async fn read_password(from_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if from_stdin {
        return read_line();
    }
    anyhow::ensure!(
        std::io::stdin().is_terminal(),
        "stdin is not a terminal; pass --password-stdin to read the owner password from stdin"
    );
    let first = prompt_hidden("Owner password: ").await?;
    let second = prompt_hidden("Repeat owner password: ").await?;
    anyhow::ensure!(*first == *second, "the two passwords do not match");
    Ok(first)
}

/// One line from stdin without its line ending.
fn read_line() -> anyhow::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::with_capacity(256));
    std::io::stdin().lock().read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

/// Prompt with echo off. Ctrl-C during the prompt restores echo before the
/// process exits; other ways of dying mid-prompt (SIGTERM, SIGHUP, a kill)
/// can leave it off, see the README.
async fn prompt_hidden(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let echo = EchoOff::new()?;
    let read = tokio::task::spawn_blocking(read_line);
    let line = tokio::select! {
        line = read => line.context("password prompt")?,
        _ = tokio::signal::ctrl_c() => {
            drop(echo);
            eprintln!();
            // Exit here: returning would wait on the blocked stdin read.
            std::process::exit(130);
        }
    };
    drop(echo);
    eprintln!();
    line
}

/// Terminal echo off for the guard's lifetime. Without it the password
/// would appear on screen and in scrollback, so failure refuses the prompt.
#[cfg(unix)]
struct EchoOff;

#[cfg(unix)]
impl EchoOff {
    fn new() -> anyhow::Result<Self> {
        let off = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status()
            .is_ok_and(|s| s.success());
        anyhow::ensure!(
            off,
            "cannot turn off terminal echo; pass --password-stdin instead"
        );
        Ok(EchoOff)
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();
    }
}

#[cfg(windows)]
struct EchoOff {
    handle: std::os::windows::io::RawHandle,
    mode: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleMode(console: std::os::windows::io::RawHandle, mode: *mut u32) -> i32;
    fn SetConsoleMode(console: std::os::windows::io::RawHandle, mode: u32) -> i32;
}

#[cfg(windows)]
impl EchoOff {
    fn new() -> anyhow::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;
        let handle = std::io::stdin().as_raw_handle();
        let mut mode = 0u32;
        // SAFETY: `handle` is this process's stdin handle, which stays valid
        // for the process lifetime; both calls only read or set its mode.
        let off = unsafe {
            GetConsoleMode(handle, &mut mode) != 0
                && SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) != 0
        };
        anyhow::ensure!(
            off,
            "cannot turn off console echo; pass --password-stdin instead"
        );
        Ok(Self { handle, mode })
    }
}

#[cfg(windows)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the mode read in `new` on the same handle.
        unsafe {
            SetConsoleMode(self.handle, self.mode);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_each_command_and_rejects_everything_else() {
        assert_eq!(parse(&args("")), Ok(Command::Serve));
        assert_eq!(parse(&args("identity init")), Ok(Command::IdentityInit));
        assert_eq!(parse(&args("identity show")), Ok(Command::IdentityShow));
        assert_eq!(
            parse(&args(
                "tenant create --owner-username alice --slug acme --password-stdin"
            )),
            Ok(Command::TenantCreate {
                slug: "acme".into(),
                owner_username: "alice".into(),
                password_stdin: true,
            })
        );
        assert_eq!(
            parse(&args(
                "tenant confirm-first-device --tenant acme --device 000102030405060708090a0b0c0d0e0f"
            )),
            Ok(Command::ConfirmFirstDevice {
                slug: "acme".into(),
                device_id: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            })
        );
        assert_eq!(parse(&args("restore status")), Ok(Command::RestoreStatus));
        assert_eq!(
            parse(&args("restore export-heads --backup b.db --out o")),
            Ok(Command::RestoreExportHeads {
                backup: "b.db".into(),
                out: "o".into(),
            })
        );
        assert_eq!(
            parse(&args(
                "restore prepare --backup b.db --txn 000102030405060708090a0b0c0d0e0f"
            )),
            Ok(Command::RestorePrepare {
                backup: "b.db".into(),
                txn: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            })
        );
        assert_eq!(
            parse(&args("restore commit --retire")),
            Ok(Command::RestoreCommit { retire: true })
        );
        assert_eq!(
            parse(&args("restore abort --orphans")),
            Ok(Command::RestoreAbort {
                orphans: true,
                delete_archives: false
            })
        );
        assert_eq!(
            parse(&args("restore abort --orphans --delete-archives")),
            Ok(Command::RestoreAbort {
                orphans: true,
                delete_archives: true
            })
        );
        assert_eq!(
            parse(&args(
                "restore withdraw-transitions --tenant 000102030405060708090a0b0c0d0e0f"
            )),
            Ok(Command::RestoreWithdrawTransitions {
                tenant: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            })
        );
        assert_eq!(
            parse(&args("tenant first-device-status --tenant acme")),
            Ok(Command::FirstDeviceStatus {
                slug: "acme".into()
            })
        );
        for bad in [
            "tenant confirm-first-device --tenant acme",
            "tenant confirm-first-device --tenant acme --device 0001",
            "tenant cancel-first-device acme",
            "identity",
            "identity init extra",
            "identity repair",
            "restore",
            "restore prepare --backup b.db",
            "restore prepare --backup b.db --txn 00",
            "restore commit --force",
            "restore abort now",
            "serve",
            "--help",
            "tenant create --slug acme",
            "tenant create --slug acme --owner-username alice --password hunter2long",
            "tenant create --slug acme --owner-username alice hunter2long",
            "tenant create --slug --owner-username alice",
            "tenant create --slug a --slug b --owner-username alice",
        ] {
            let err = parse(&args(bad)).unwrap_err();
            assert!(!err.contains("hunter2"), "{bad}: {err}");
        }
    }

    #[test]
    fn owner_usernames_are_bounded_and_printable() {
        let longest = "a".repeat(MAX_USERNAME_CHARS);
        for ok in [
            "alice",
            "Alice Smith",
            "ann.o'neil",
            &longest,
            "\u{e9}lodie",
        ] {
            assert!(valid_username(ok), "{ok:?}");
        }
        let too_long = "a".repeat(MAX_USERNAME_CHARS + 1);
        for bad in [
            "",
            " alice",
            "alice ",
            "\talice",
            "al\nice",
            "al\u{7}ice",
            &too_long,
        ] {
            assert!(!valid_username(bad), "{bad:?}");
        }
    }

    #[test]
    fn slugs_are_restricted() {
        for ok in ["acme", "a", "team-2"] {
            assert!(valid_slug(ok), "{ok}");
        }
        for bad in ["", "-acme", "Acme", "a b", "a/b", &"a".repeat(64)] {
            assert!(!valid_slug(bad), "{bad}");
        }
    }

    #[test]
    fn a_second_lock_holder_is_refused_until_the_first_releases() {
        let dir = std::env::temp_dir().join(format!("shardx-lock-{}", std::process::id()));
        let d = dir.to_string_lossy().into_owned();
        let first = lock_data_dir(&d).unwrap();
        let err = lock_data_dir(&d).unwrap_err().to_string();
        assert!(err.contains("another instance holds"), "{err}");
        drop(first);
        drop(lock_data_dir(&d).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
