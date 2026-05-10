//! Shared CLI verbosity flags for `msb` and its hidden runtime subcommands.

use std::fs::OpenOptions;
use std::sync::Mutex;

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

/// Install a tracing subscriber for the selected level, plus an optional
/// `target: "policy_deny"` capture layer that writes one JSON-formatted
/// event per line to the path in `MSB_DENY_LOG_PATH`. The capture layer
/// is the only way library callers (who spawn `msb` as a subprocess via
/// `microsandbox::Sandbox::create()`) can observe network policy denies,
/// because the deny logic runs in the spawned process and `tracing` is
/// process-global.
///
/// Both layers are stock `tracing_subscriber::fmt::layer()` instances:
/// the stderr layer uses the human-formatted output, the deny layer
/// uses `.json()` so consumers can `serde_json::from_str` each line.
///
/// `ansi` controls whether the stderr formatter emits color escape
/// sequences. Pass `true` for the user-facing CLI (colored output on
/// a TTY) and `false` for the sandbox subprocess (whose stderr is
/// captured into `runtime.log`, where escape codes would be junk).
///
/// If no log level is selected and `MSB_DENY_LOG_PATH` is unset,
/// logging stays fully disabled — preserves the old behaviour for
/// unmodified callers.
pub fn init_tracing(log_level: Option<LogLevel>, ansi: bool) {
    let stderr_layer = log_level.map(|level| {
        // Silence oci_client logs — the crate logs the auth token in debug mode
        // See: https://github.com/oras-project/rust-oci-client/issues/254
        let filter = EnvFilter::new(level.as_tracing_level().to_string())
            .add_directive("oci_client=info".parse::<Directive>().unwrap());
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(ansi)
            .with_filter(filter)
    });

    let deny_layer = std::env::var("MSB_DENY_LOG_PATH").ok().and_then(|path| {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok()?;
        Some(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(Mutex::new(file))
                .with_ansi(false)
                .with_filter(Targets::new().with_target("policy_deny", Level::TRACE)),
        )
    });

    if stderr_layer.is_none() && deny_layer.is_none() {
        return;
    }

    // try_init so we don't panic if the host process already initialised a
    // subscriber (msb-ffi callers may have one for diagnostic purposes).
    let _ = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(deny_layer)
        .try_init();
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
        Sandbox,
        Run,
    }

    #[test]
    fn test_global_log_flag_after_subcommand() {
        let cli = TestCli::parse_from(["msb", "run", "--debug"]);
        assert_eq!(cli.logs.selected_level(), Some(LogLevel::Debug));
    }

    #[test]
    fn test_no_log_flag_means_silent() {
        let cli = TestCli::parse_from(["msb", "sandbox"]);
        assert_eq!(cli.logs.selected_level(), None);
    }

    #[test]
    fn test_log_flags_conflict() {
        let err = TestCli::try_parse_from(["msb", "--info", "--debug", "sandbox"]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("--debug"));
        assert!(rendered.contains("--info"));
    }

    #[test]
    fn deny_log_layer_writes_only_policy_deny_target() {
        // Build the deny layer manually using the same configuration that
        // `init_tracing` uses internally, so the test stays in sync if
        // that wiring changes.
        let path = std::env::temp_dir().join(format!("msb-deny-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(Mutex::new(file))
            .with_ansi(false)
            .with_filter(Targets::new().with_target("policy_deny", Level::TRACE));

        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "policy_deny", host = "example.com", port = 443u32, "denied");
            tracing::debug!(target: "other_target", host = "ignored.example", "should not appear");
        });

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one deny line, got: {body}"
        );
        // tracing-subscriber's JSON formatter writes `target` outside of
        // `fields`. Schema (per the formatter, current shape):
        //   {"timestamp":"...","level":"DEBUG","fields":{...},"target":"policy_deny"}
        // We don't assert the exact key order — just the substantive
        // fields downstream consumers depend on.
        assert!(
            lines[0].contains("\"target\":\"policy_deny\""),
            "got: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("\"host\":\"example.com\""),
            "got: {}",
            lines[0]
        );
        assert!(lines[0].contains("\"port\":443"), "got: {}", lines[0]);

        let _ = std::fs::remove_file(&path);
    }
}
