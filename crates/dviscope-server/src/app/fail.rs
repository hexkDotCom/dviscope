//! Fail points for transaction failure injection (acceptance A20): a test arms one named
//! point; the next operation reaching it fails with an internal error, which rolls its
//! transaction back. Unarmed (always, outside tests) a point does nothing.

use std::sync::Mutex;

use crate::error::AppError;

static ARMED: Mutex<Option<&'static str>> = Mutex::new(None);

/// Arms (or, with `None`, disarms) a fail point.
pub fn arm(point: Option<&'static str>) {
    if let Ok(mut a) = ARMED.lock() {
        *a = point;
    }
}

/// Fails once if `name` is armed (and disarms it).
///
/// # Errors
/// The injected failure.
pub fn point(name: &str) -> Result<(), AppError> {
    let hit = ARMED
        .lock()
        .map(|mut a| {
            if *a == Some(name) {
                *a = None;
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if hit {
        Err(AppError::internal("injected failure"))
    } else {
        Ok(())
    }
}
