#![forbid(unsafe_code)]

use clap::Parser;
use pccs_rs::config::{
    Cli, Command, Config, ConfigCommand, DbCommand, DEFAULT_ADMIN_TOKEN_HASH,
    DEFAULT_USER_TOKEN_HASH,
};
use pccs_rs::server::{configure_http, serve_http, tune_tcp, SHUTDOWN_GRACE};
use pccs_rs::{app_state, create_app};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

fn main() {
    match Cli::parse().command {
        Command::Serve(args) => serve_main(Config::from(args)),
        Command::Config(cmd) => {
            if let Err(e) = run_config(cmd) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Command::Db(cmd) => {
            let result = match cmd.command {
                DbCommand::ImportIntel { snapshot, db_path } => {
                    pccs_rs::intel_import::import_intel(&snapshot, &db_path)
                }
            };
            match result {
                Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
                Err(e) => {
                    eprintln!("Intel import failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn run_config(cmd: pccs_rs::config::ConfigCmd) -> Result<(), String> {
    match cmd.command {
        ConfigCommand::Import { from, to } => {
            pccs_rs::config::import_pccs_json(&from, &to)?;
            println!("wrote {}", to.display());
            Ok(())
        }
    }
}

#[tokio::main]
async fn serve_main(cfg: Config) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::try_new(&cfg.log_level).unwrap_or_else(|e| {
            eprintln!("invalid LogLevel {:?}: {e}; using info", cfg.log_level);
            EnvFilter::new("info")
        })
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Config is parsed before the subscriber exists, so anything it wanted to
    // say was collected instead of logged. Drain it now that logging works.
    for w in &cfg.warnings {
        tracing::warn!("{w}");
    }

    run(cfg).await;
}

async fn run(cfg: Config) {
    let addr = resolve_bind_addr(&cfg.bind_addr());

    tracing::info!(
        "pccs-rs starting mode={} uri={} db={} version={} rocksdb(block_cache={}MiB write_buffer={}MiB max_write_buffers={} max_open_files={})",
        cfg.cache_mode.as_str(),
        cfg.uri,
        cfg.db_path.display(),
        cfg.pcs_version(),
        cfg.block_cache_mb,
        cfg.write_buffer_mb,
        cfg.max_write_buffers,
        cfg.max_open_files
    );
    cfg.validate_token_hashes();
    warn_on_dev_tokens(&cfg);
    warn_on_self_upstream(&cfg, addr);

    let state = app_state(cfg.clone());
    let metrics_listener =
        start_metrics_listener(cfg.metrics_listen, state.cache.store.metrics.clone())
            .await
            .unwrap_or_else(|e| {
                eprintln!("metrics listener: {e}");
                std::process::exit(1);
            });
    let scheduler = spawn_refresh_scheduler(state.cache.clone(), cfg.refresh_schedule.clone());
    // No handler-cancelling timeout layer here. Node's `server.requestTimeout`
    // bounds only *receiving* the request, never producing the response; a
    // tower-http `TimeoutLayer` would instead abort the handler mid-flight —
    // turning a slow LAZY miss (upstream budget is 120s) or an admin
    // `/refresh` into a 408 and, worse, cancelling it between two writes.
    // Request-receive is bounded by hyper's `header_read_timeout` (headers)
    // plus the body-read timeout in `error::PccsJson` (body).
    let app = create_app(state.clone());

    if cfg.https {
        rustls::crypto::ring::default_provider().install_default().ok();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cfg.cert, &cfg.key)
            .await
            .unwrap_or_else(|e| {
                eprintln!(
                    "HTTPS cert/key missing or invalid ({} / {}): {e}",
                    cfg.cert.display(),
                    cfg.key.display()
                );
                std::process::exit(1);
            });
        tracing::info!("HTTPS Server is running on: https://{}", addr);
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            shutdown_handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
        });
        // `axum_server` 0.7 has no first-byte timeout of its own, so on the TLS
        // path `HeadersTimeoutSeconds` bounds the TLS handshake instead: a peer
        // that connects and then says nothing is dropped when the handshake
        // times out. Once the handshake is done, the hyper builder below governs
        // the request head exactly like the plain-HTTP path.
        let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(tls)
            .handshake_timeout(Duration::from_secs(cfg.headers_timeout_secs.max(1)))
            .acceptor(TunedAcceptor);
        let mut server = axum_server::bind(addr).acceptor(acceptor).handle(handle);
        configure_http(server.http_builder(), &cfg);
        state.startup.mark_started();
        if let Err(e) = server.serve(app.into_make_service()).await {
            tracing::error!("https server: {e}");
        }
    } else {
        tracing::info!("HTTP Server is running on: http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
            eprintln!("bind {addr}: {e}");
            std::process::exit(1);
        });
        state.startup.mark_started();
        serve_http(listener, app, &cfg, shutdown_signal()).await;
    }

    // Let RocksDB close before the process exits.
    scheduler.abort();
    if let Some(listener) = metrics_listener {
        listener.stop().await;
    }
    drop(state);
}

struct MetricsListener {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl MetricsListener {
    async fn stop(mut self) {
        tracing::debug!("stopping metrics listener {}", self.addr);
        let _ = self.shutdown.send(());
        if tokio::time::timeout(SHUTDOWN_GRACE, &mut self.task).await.is_err() {
            self.task.abort();
        }
    }
}

/// Bind before starting the task, so an invalid or occupied address is fatal
/// rather than silently leaving an advertised metrics endpoint unavailable.
async fn start_metrics_listener(
    addr: Option<SocketAddr>,
    metrics: Arc<pccs_rs::metrics::Metrics>,
) -> std::io::Result<Option<MetricsListener>> {
    let Some(addr) = addr else { return Ok(None) };
    if !addr.ip().is_loopback() {
        tracing::warn!("metrics listener {addr} is not loopback; metrics have no authentication");
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;
    tracing::info!("metrics listener running on http://{addr}/metrics");
    let (shutdown, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, metrics.router())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
        {
            tracing::error!("metrics listener: {e}");
        }
    });
    Ok(Some(MetricsListener { addr, shutdown, task }))
}

/// The TLS path goes through `axum_server`, which owns its accept loop; this
/// acceptor is spliced in front of the rustls one so accepted sockets get the
/// same treatment as on the plain-HTTP path.
#[derive(Clone, Copy)]
struct TunedAcceptor;

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for TunedAcceptor {
    type Stream = tokio::net::TcpStream;
    type Service = S;
    type Future = std::future::Ready<std::io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        tune_tcp(&stream);
        std::future::ready(Ok((stream, service)))
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::warn!("SIGTERM handler: {e}"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// A hostname is fine (Node binds `hosts` verbatim); an unresolvable one is fatal.
fn resolve_bind_addr(bind: &str) -> SocketAddr {
    match bind.to_socket_addrs() {
        Ok(mut addrs) => addrs.next().unwrap_or_else(|| {
            eprintln!("bind address {bind:?} resolved to no address");
            std::process::exit(1);
        }),
        Err(e) => {
            eprintln!("bind address {bind:?}: {e}");
            std::process::exit(1);
        }
    }
}

fn warn_on_dev_tokens(cfg: &Config) {
    if cfg.user_token_hash == DEFAULT_USER_TOKEN_HASH
        || cfg.admin_token_hash == DEFAULT_ADMIN_TOKEN_HASH
    {
        tracing::warn!(
            "built-in dev token hashes are in use (raw tokens \"user\" / \"admin\"); \
             never run this configuration in production"
        );
    }
}

/// An upstream URI pointing back at this service turns every cache miss into recursion.
fn warn_on_self_upstream(cfg: &Config, addr: SocketAddr) {
    warn_if_uri_is_self(
        cfg,
        addr,
        &cfg.uri,
        "upstream uri host",
        "Set uri to the Intel PCS (or another PCCS).",
    );
    warn_if_uri_is_self(
        cfg,
        addr,
        &cfg.amd_kds_uri,
        "amd_kds_uri host",
        "Set amd_kds_uri to the AMD KDS.",
    );
    warn_if_uri_is_self(
        cfg,
        addr,
        &cfg.nvidia_rim_uri,
        "nvidia_rim_uri host",
        "Set nvidia_rim_uri to the NVIDIA RIM service.",
    );
    warn_if_uri_is_self(
        cfg,
        addr,
        &cfg.nvidia_ocsp_uri,
        "nvidia_ocsp_uri host",
        "Set nvidia_ocsp_uri to the NVIDIA OCSP responder.",
    );
}

fn warn_if_uri_is_self(cfg: &Config, addr: SocketAddr, uri: &str, label: &str, advice: &str) {
    let Some(host) = pccs_rs::config::uri_host(uri) else {
        return;
    };
    let same_host = host == cfg.host.to_ascii_lowercase()
        || host.to_socket_addrs().map(|mut a| a.any(|a| a.ip() == addr.ip())).unwrap_or(false);
    if same_host {
        tracing::warn!(
            "{label} {host} looks like this service; a cache miss would call back into pccs-rs. {advice}"
        );
    }
}

fn spawn_refresh_scheduler(
    cache: Arc<pccs_rs::cache::Cache>,
    schedule: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let sched = match cron::Schedule::from_str(&schedule) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("invalid RefreshSchedule {schedule}: {e}; using daily 01:00");
                cron::Schedule::from_str("0 0 1 * * *").expect("default cron")
            }
        };
        loop {
            let now = chrono::Utc::now();
            let Some(next) = sched.upcoming(chrono::Utc).next() else {
                tracing::error!(
                    "RefreshSchedule {schedule} has no future run; scheduled refresh disabled"
                );
                break;
            };
            let wait = (next - now).to_std().unwrap_or(std::time::Duration::from_secs(60));
            tracing::info!("next scheduled refresh at {next} (in {wait:?})");
            tokio::time::sleep(wait).await;
            match cache.scheduled_refresh().await {
                Ok(()) => tracing::info!("scheduled refresh complete"),
                Err(e) => tracing::warn!("scheduled refresh: {e}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-global log capture: tracing allows one global subscriber, so
    /// every test in this binary shares the buffer and asserts with `contains`.
    fn captured_logs() -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
        use std::sync::{Mutex, OnceLock};
        static LOGS: OnceLock<std::sync::Arc<Mutex<Vec<u8>>>> = OnceLock::new();
        LOGS.get_or_init(|| {
            let buf = std::sync::Arc::new(Mutex::new(Vec::new()));
            struct Writer(std::sync::Arc<Mutex<Vec<u8>>>);
            impl std::io::Write for Writer {
                fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(data);
                    Ok(data.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            impl tracing_subscriber::fmt::MakeWriter<'_> for Writer {
                type Writer = Self;
                fn make_writer(&self) -> Self::Writer {
                    Writer(self.0.clone())
                }
            }
            let _ = tracing_subscriber::fmt()
                .with_writer(Writer(buf.clone()))
                .with_ansi(false)
                .try_init();
            buf
        })
        .clone()
    }

    fn logs_contain(buf: &std::sync::Mutex<Vec<u8>>, needle: &str) -> bool {
        String::from_utf8_lossy(&buf.lock().unwrap()).contains(needle)
    }

    #[tokio::test]
    async fn metrics_listener_is_disabled_by_default_and_separate_when_enabled() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let metrics = Arc::new(pccs_rs::metrics::Metrics::new());
        assert!(start_metrics_listener(Config::default().metrics_listen, metrics.clone())
            .await
            .unwrap()
            .is_none());
        let listener = start_metrics_listener(Some("127.0.0.1:0".parse().unwrap()), metrics)
            .await
            .unwrap()
            .unwrap();
        let addr = listener.addr;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("text/plain; version=0.0.4"));
        assert!(response.contains("pccs_build_info"));
        listener.stop().await;
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    }

    #[tokio::test]
    async fn metrics_nonloopback_warns_but_binds_and_bind_errors_propagate() {
        let logs = captured_logs();
        let needle = "is not loopback; metrics have no authentication";
        let before = log_count(&logs, needle);
        let metrics = Arc::new(pccs_rs::metrics::Metrics::new());
        let listener = start_metrics_listener(Some("0.0.0.0:0".parse().unwrap()), metrics.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_count(&logs, needle), before + 1);
        assert!(start_metrics_listener(Some(listener.addr), metrics).await.is_err());
        listener.stop().await;
    }

    #[test]
    fn resolve_bind_addr_accepts_hosts_and_ips() {
        let addr = resolve_bind_addr("127.0.0.1:8081");
        assert_eq!(addr.port(), 8081);
        let addr = resolve_bind_addr("localhost:9090");
        assert_eq!(addr.port(), 9090);
    }

    /// Occurrences of `needle` in the shared log stream. The stream is
    /// process-global and tests run in parallel, so every assertion is a
    /// before/after count on a needle only this test can produce.
    fn log_count(logs: &std::sync::Mutex<Vec<u8>>, needle: &str) -> usize {
        String::from_utf8_lossy(&logs.lock().unwrap()).matches(needle).count()
    }

    #[test]
    fn warn_helpers_log_exactly_when_they_should() {
        let logs = captured_logs();
        let dev_tokens = "built-in dev token hashes are in use";
        let self_upstream = "looks like this service";
        let mut cfg = Config::default();

        let before = log_count(&logs, dev_tokens);
        warn_on_dev_tokens(&cfg);
        assert_eq!(log_count(&logs, dev_tokens), before, "no dev tokens configured: no warning");
        cfg.user_token_hash = DEFAULT_USER_TOKEN_HASH.into();
        warn_on_dev_tokens(&cfg);
        assert_eq!(log_count(&logs, dev_tokens), before + 1);

        // No URI host at all: nothing to compare.
        let before = log_count(&logs, self_upstream);
        cfg.uri = String::new();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(log_count(&logs, self_upstream), before, "empty upstream must not warn");
        // Upstream on this very address: warns.
        cfg.uri = "http://127.0.0.1:8081/sgx/certification/v4/".into();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(log_count(&logs, self_upstream), before + 1);
        // Unresolvable upstream host: no warning, no panic.
        cfg.uri = "https://nonexistent.invalid/sgx/".into();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(log_count(&logs, self_upstream), before + 1);

        cfg.uri = String::new();
        cfg.amd_kds_uri = "http://127.0.0.1:8081/vcek/v1".into();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(log_count(&logs, self_upstream), before + 2);
        cfg.amd_kds_uri = String::new();
        cfg.nvidia_rim_uri = "http://127.0.0.1:8081/v1/rim".into();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(log_count(&logs, self_upstream), before + 3);
        cfg.nvidia_rim_uri = String::new();
        cfg.nvidia_ocsp_uri = "http://127.0.0.1:8081/ocsp".into();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(log_count(&logs, self_upstream), before + 4);
    }

    #[tokio::test]
    async fn tune_tcp_and_acceptor_survive_a_live_socket() {
        use axum_server::accept::Accept;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let (stream, _) = listener.accept().await.unwrap();
        tune_tcp(&stream);
        let (stream, _service) = TunedAcceptor.accept(stream, ()).await.unwrap();
        drop(stream);
        client.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_refresh_schedule_falls_back_to_the_default() {
        let logs = captured_logs();
        let cfg = Config::test_default();
        let cache = pccs_rs::cache::build_cache(&cfg).unwrap();
        let handle = spawn_refresh_scheduler(cache, "not a cron".to_string());
        // The fallback logs both the parse failure and the next run computed
        // from the daily-01:00 default.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if logs_contain(&logs, "invalid RefreshSchedule")
                    && logs_contain(&logs, "using daily 01:00")
                    && logs_contain(&logs, "next scheduled refresh at")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("scheduler never logged the fallback");
        assert!(!handle.is_finished(), "the task keeps scheduling");
        handle.abort();
    }
}
