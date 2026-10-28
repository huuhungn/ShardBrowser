//! Shared ShardX logic used by the launcher (and, later, the Rust SDK):
//!
//! - [`oscrypt`] — Chromium `os_crypt` v10 cookie/secret encryption, with the
//!   key handled explicitly so encrypt/decrypt can be re-keyed across machines.
//! - [`cookies`] — read/write a profile's Chromium `Cookies` SQLite DB.
//! - [`snapshot`] — pack/unpack a `user-data-dir` to portable bytes, excluding
//!   cache and normalizing the (machine-bound) cookie encryption so a snapshot
//!   taken on one machine restores correctly on another (incl. Mac↔Windows).

pub mod approval_receipt;
pub mod authz_record;
pub mod backup;
pub mod backup_file;
pub mod canonical;
pub mod cookies;
pub mod envelope;
pub mod envelope_v2;
pub mod fallback_key_file;
pub mod fleet_grants;
pub mod fleet_lifecycle;
pub mod fleet_manifest;
pub mod grants;
pub mod keys;
pub mod logins;
pub mod mutation;
pub mod oscrypt;
pub mod passphrase;
pub mod portable;
pub mod recovery_bundle;
pub mod restore_epoch;
pub mod session_binding;
pub mod signing;
pub mod snapshot;
pub mod snapshot_v2;
pub mod trust_chain;
pub mod trust_evidence;
pub mod webdata;

pub use oscrypt::LocalCrypt;
pub use portable::{PortableCookie, PortableLogin, PortableSecret, PortableState};
