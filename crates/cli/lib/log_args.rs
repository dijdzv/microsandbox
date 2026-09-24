//! Shared CLI verbosity flags for `msb` and its hidden runtime subcommands.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use clap::Args;
use microsandbox_runtime::logging::LogLevel;
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{Directive, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Mutually-exclusive tracing verbosity flags.
#[derive(Debug, Clone, Default, Args)]
pub struct LogArgs {
    /// Show error-level diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["warn", "info", "debug", "trace"])]
    pub error: bool,

    /// Show warning and error diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["error", "info", "debug", "trace"])]
    pub warn: bool,

    /// Show info, warning, and error diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["error", "warn", "debug", "trace"])]
    pub info: bool,

    /// Show debug and higher diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["error", "warn", "info", "trace"])]
    pub debug: bool,

    /// Show all diagnostic logs (most verbose).
    #[arg(long, global = true, conflicts_with_all = ["error", "warn", "info", "debug"])]
    pub trace: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Install stderr tracing and an optional policy-deny JSONL capture layer.
///
/// `ansi` controls whether the formatter emits color escape sequences.
/// Pass `true` for the user-facing CLI (colored output on a TTY) and
/// `false` for the sandbox subprocess (whose stderr is captured into
/// `runtime.log`, where escape codes would be junk).
///
/// A configured capture path must open successfully before startup. Silently
/// dropping the layer would leave policy enforcement active but unobservable.
///
/// # Errors
///
/// Returns an I/O error when `MSB_DENY_LOG_PATH` cannot be opened.
pub fn init_tracing(log_level: Option<LogLevel>, ansi: bool) -> io::Result<()> {
    let deny_file = std::env::var_os("MSB_DENY_LOG_PATH")
        .map(|path| open_deny_log_file(Path::new(&path)))
        .transpose()?;
    let stderr_layer = log_level.map(|level| {
        // Silence oci_client logs — the crate logs the auth token in debug mode.
        // See: https://github.com/oras-project/rust-oci-client/issues/254
        let filter = EnvFilter::new(level.as_str())
            .add_directive("oci_client=info".parse::<Directive>().unwrap());
        tracing_subscriber::fmt::layer()
            .with_writer(io::stderr)
            .with_ansi(ansi)
            .with_filter(filter)
    });
    let deny_layer = deny_file.map(|file| {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(Mutex::new(file))
            .with_ansi(false)
            .with_filter(Targets::new().with_target("policy_deny", Level::TRACE))
    });
    if stderr_layer.is_some() || deny_layer.is_some() {
        tracing_subscriber::registry()
            .with(stderr_layer)
            .with(deny_layer)
            .init();
    }
    Ok(())
}

/// Open a deny capture file without making a new file world-readable.
fn open_deny_log_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LogArgs {
    /// Return the selected log level, if any.
    pub const fn selected_level(&self) -> Option<LogLevel> {
        if self.error {
            Some(LogLevel::Error)
        } else if self.warn {
            Some(LogLevel::Warn)
        } else if self.info {
            Some(LogLevel::Info)
        } else if self.debug {
            Some(LogLevel::Debug)
        } else if self.trace {
            Some(LogLevel::Trace)
        } else {
            None
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, Subcommand};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        logs: LogArgs,

        #[command(subcommand)]
        command: TestCommand,
    }

    #[derive(Debug, Subcommand)]
    enum TestCommand {
        Machine,
        Run,
    }

    #[test]
    fn test_global_log_flag_after_subcommand() {
        let cli = TestCli::parse_from(["msb", "run", "--debug"]);
        assert_eq!(cli.logs.selected_level(), Some(LogLevel::Debug));
    }

    #[test]
    fn test_no_log_flag_means_silent() {
        let cli = TestCli::parse_from(["msb", "machine"]);
        assert_eq!(cli.logs.selected_level(), None);
    }

    #[test]
    fn test_log_flags_conflict() {
        let err = TestCli::try_parse_from(["msb", "--info", "--debug", "machine"]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("--debug"));
        assert!(rendered.contains("--info"));
    }

    #[test]
    fn deny_capture_path_open_failure_is_not_silent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_deny_log_file(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn deny_capture_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy-deny.jsonl");
        let file = open_deny_log_file(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
}
