//! Reporting and the owned guest cleanup chain share a signal, not a dependency.
use std::future::Future;
use tokio::time::Instant;

use super::ObservabilityReporter;
use crate::api::shutdown::cleanup_phase;

pub const REPORTER_SHUTDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

pub async fn shutdown_with_reporter(
    mut reporter: Option<ObservabilityReporter>,
    deadline: Instant,
    cleanup: impl Future<Output = std::io::Result<()>>,
) -> std::io::Result<()> {
    let reporting = async {
        if let Some(handle) = reporter.as_mut() {
            cleanup_phase("reporter", handle.shutdown_until(deadline)).await
        } else {
            Ok(())
        }
    };
    // Never put reporting in front of preservation or put the owned cleanup
    // under the reporter timeout. Both futures are joined even on errors.
    let (cleanup_result, report_result) = tokio::join!(cleanup, reporting);
    match (report_result, cleanup_result) {
        (Ok(()), result) => result,
        (Err(report), Ok(())) => Err(std::io::Error::other(report)),
        (Err(report), Err(cleanup)) => Err(std::io::Error::other(format!(
            "{cleanup}; reporter: {report}"
        ))),
    }
}
