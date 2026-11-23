//! Published limits. Exceeding one is an explicit rejection, never a
//! silent truncation into a pass.

/// Maximum encoded (possibly compressed) request body.
pub const MAX_ENCODED_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Maximum decoded request body.
pub const MAX_DECODED_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// Maximum decompression ratio, enforced while streaming.
pub const MAX_COMPRESSION_RATIO: usize = 20;
/// Maximum records per ingest batch.
pub const MAX_RECORDS_PER_BATCH: usize = 1_000;
/// Maximum serialized size of one record.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// Maximum JSON nesting depth.
pub const MAX_JSON_DEPTH: usize = 32;
/// Maximum message string length (bytes).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Maximum field string length (bytes).
pub const MAX_FIELD_BYTES: usize = 4 * 1024;
/// Maximum accounting buckets per evidence.
pub const MAX_BUCKETS: usize = 1_024;
/// Maximum families per evidence.
pub const MAX_FAMILIES: usize = 512;
/// Maximum example events per evidence.
pub const MAX_EVENTS: usize = 300;
/// Serialized budget of buckets and families together.
pub const MAX_ACCOUNTING_BYTES: usize = 256 * 1024;
/// Serialized budget of example events.
pub const MAX_EVENTS_BYTES: usize = 512 * 1024;
/// Serialized budget of the excerpt.
pub const MAX_EXCERPT_BYTES: usize = 64 * 1024;
/// Maximum log line length before it is cut.
pub const MAX_LINE_BYTES: usize = 16 * 1024;
/// Maximum assembled record size.
pub const MAX_RECORD_ASSEMBLY_BYTES: usize = 256 * 1024;
