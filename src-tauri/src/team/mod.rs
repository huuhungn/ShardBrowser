//! Team sync state kept in the local team database (plan 11.1, layout at
//! L2431: `src-tauri/src/team/{db,...}.rs`).
//!
//! Only the schema guard and the W6 trust ledger live here so far. Team
//! settings, fleet keys and the custody bootstrap stay in their JSON files:
//! the plan migrates no local JSON wholesale (L91).

pub mod db;
pub mod ledger;
pub mod sync;
