//! Team sync state kept in the local team database (plan 11.1, layout at
//! L2431: `src-tauri/src/team/{db,...}.rs`).
//!
//! Only the schema guard, the W6 trust ledger, published-profile sync and the
//! restore and downgrade journals with the launcher downgrade flow live here
//! so far. Team settings, fleet keys and the custody bootstrap stay in their
//! JSON files: the plan migrates no local JSON wholesale (L91).

pub mod db;
pub mod downgrade;
pub mod journal;
pub mod ledger;
pub mod records;
pub mod sync;
