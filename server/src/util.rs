/// RFC3339 UTC timestamp — the on-disk format for every `*_at` column.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Unix time in milliseconds, the unit of every v2 `*_ms` column.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Fresh UUID v4 string — used for every primary key.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// RFC3339 timestamp `secs` from now (used for lock lease expiry).
pub fn rfc3339_in(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
}

/// True if an RFC3339 timestamp is in the past (or unparseable → treat as expired).
pub fn is_past(ts: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| t.with_timezone(&chrono::Utc) < chrono::Utc::now())
        .unwrap_or(true)
}

/// `n` as a SQLite integer; one past `i64::MAX` is refused, never wrapped
/// (plan G2-45).
pub fn sql_int(n: u64) -> Result<i64, crate::error::AppError> {
    i64::try_from(n).map_err(|_| {
        crate::error::AppError::Coded(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "WIRE_INTEGER_OUT_OF_RANGE",
            "an integer is outside the storage range".into(),
        )
    })
}

/// A stored unsigned column; a negative value is corrupt, never wrapped.
pub fn stored_uint(n: i64) -> Result<u64, crate::error::AppError> {
    u64::try_from(n)
        .map_err(|_| crate::error::AppError::Internal("a stored unsigned value is negative".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_cross_the_storage_boundary_only_in_range() {
        assert_eq!(sql_int(0).unwrap(), 0);
        assert_eq!(sql_int(i64::MAX as u64).unwrap(), i64::MAX);
        assert!(sql_int(i64::MAX as u64 + 1).is_err());
        assert!(sql_int(u64::MAX).is_err());
        assert_eq!(stored_uint(i64::MAX).unwrap(), i64::MAX as u64);
        assert!(stored_uint(-1).is_err());
    }
}
