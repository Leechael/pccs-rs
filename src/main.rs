use clap::Parser;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use pccs_rs::config::{Cli, Config, DEFAULT_ADMIN_TOKEN_HASH, DEFAULT_USER_TOKEN_HASH};
use pccs_rs::{app_state, create_app};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// How long in-flight requests get to finish after SIGINT / SIGTERM.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let cfg = Config::from(cli);

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
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
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
        let mut server = axum_server::bind_rustls(addr, tls).handle(handle);
        configure_http(server.http_builder(), &cfg);
        if let Err(e) = server.serve(app.into_make_service()).await {
            tracing::error!("https server: {e}");
        }
    } else {
        tracing::info!("HTTP Server is running on: http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| {
                eprintln!("bind {addr}: {e}");
                std::process::exit(1);
            });
        serve_http(listener, app, &cfg).await;
    }

    // Let RocksDB close before the process exits.
    scheduler.abort();
    drop(state);
}

/// Plain HTTP with the Node `pccs_server.js` connection timeouts and a
/// graceful shutdown on SIGINT / SIGTERM.
async fn serve_http(listener: tokio::net::TcpListener, app: axum::Router, cfg: &Config) {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_http(&mut builder, cfg);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown_signal());

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("accept: {e}");
                        continue;
                    }
                };
                let service = TowerToHyperService::new(app.clone());
                let conn = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .into_owned();
                let conn = graceful.watch(conn);
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("connection: {e}");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    tokio::select! {
        _ = graceful.shutdown() => {}
        _ = tokio::time::sleep(SHUTDOWN_GRACE) => {
            tracing::warn!("graceful shutdown timed out after {SHUTDOWN_GRACE:?}");
        }
    }
}

/// `HeadersTimeoutSeconds` maps onto hyper's header read timeout. Note hyper has
/// no separate keep-alive idle timeout: the same timer bounds how long an idle
/// keep-alive connection may wait for the next request head, so
/// `KeepAliveTimeoutSeconds` only acts as an upper bound here (hyper closes
/// earlier, at the headers timeout).
fn configure_http(builder: &mut auto::Builder<TokioExecutor>, cfg: &Config) {
    let headers = cfg
        .headers_timeout_secs
        .min(cfg.keepalive_timeout_secs.max(1));
    builder
        .http1()
        .timer(TokioTimer::new())
        .keep_alive(cfg.keepalive_timeout_secs > 0)
        .header_read_timeout(Some(Duration::from_secs(headers)));
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

/// `uri` pointing back at this service turns every cache miss into recursion.
fn warn_on_self_upstream(cfg: &Config, addr: SocketAddr) {
    let Some(host) = cfg.uri_host() else {
        return;
    };
    let same_host = host == cfg.host.to_ascii_lowercase()
        || host
            .to_socket_addrs()
            .map(|mut a| a.any(|a| a.ip() == addr.ip()))
            .unwrap_or(false);
    if same_host {
        tracing::warn!(
            "upstream uri host {host} looks like this service; a cache miss would call back into pccs-rs. \
             Set uri to the Intel PCS (or another PCCS)."
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
            let wait = (next - now)
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(60));
            tracing::info!("next scheduled refresh at {next} (in {wait:?})");
            tokio::time::sleep(wait).await;
            match cache.refresh(None, None).await {
                Ok(()) => tracing::info!("scheduled refresh complete"),
                Err(e) => tracing::warn!("scheduled refresh: {e}"),
            }
        }
    })
}
