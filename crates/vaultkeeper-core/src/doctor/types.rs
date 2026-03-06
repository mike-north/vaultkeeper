//! Doctor/preflight system types.

use crate::types::PreflightCheck;
use std::future::Future;
use std::pin::Pin;

/// A function that runs a named preflight check.
pub type DoctorCheckFn =
    Box<dyn Fn(&str) -> Pin<Box<dyn Future<Output = PreflightCheck> + Send>> + Send + Sync>;
