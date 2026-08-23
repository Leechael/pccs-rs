#![forbid(unsafe_code)]

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

/// TCP keepalive on accepted connections. Long-lived keep-alive connections from
/// the reverse proxy would otherwise be indistinguishable from a proxy that died
/// without a FIN, and idle NAT / load-balancer state can be dropped underneath
/// them. Not configurable on purpose: it is a transport-level liveness probe,
/// unrelated to the HTTP keep-alive idle timeout.
const TCP_KEEPALIVE: Duration = Duration::from_secs(60);

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
///
/// Accepted sockets are tuned for reuse (`TCP_NODELAY`, `SO_KEEPALIVE`) and a
/// fresh connection must produce its first byte within `HeadersTimeoutSeconds`
/// before it is handed to hyper — see `configure_http` for why that check lives
/// here and not in the hyper builder.
async fn serve_http(listener: tokio::net::TcpListener, app: axum::Router, cfg: &Config) {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_http(&mut builder, cfg);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown_signal());
    let first_byte = Duration::from_secs(cfg.headers_timeout_secs);

    // The first-byte wait must not stall the accept loop, and `GracefulShutdown`
    // is not shareable across tasks, so the wait happens in its own task and the
    // stream comes back here to be registered and served.
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel();

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
                tune_tcp(&stream);
                let tx = ready_tx.clone();
                tokio::spawn(async move {
                    if await_first_byte(&stream, first_byte).await {
                        let _ = tx.send(stream);
                    }
                });
            }
            Some(stream) = ready_rx.recv() => {
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

/// `false` means the connection is not worth serving: it stayed silent past the
/// deadline (slowloris / a probe that opens sockets and leaves), or it hung up.
/// `peek` leaves the byte in the socket buffer for hyper to read.
async fn await_first_byte(stream: &tokio::net::TcpStream, timeout: Duration) -> bool {
    if timeout.is_zero() {
        return true;
    }
    match tokio::time::timeout(timeout, stream.peek(&mut [0u8; 1])).await {
        Ok(Ok(0)) => false,
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::debug!("first byte: {e}");
            false
        }
        Err(_) => {
            tracing::debug!("no request within {timeout:?} of connect; closing");
            false
        }
    }
}

/// `TCP_NODELAY` (collateral responses are small; Nagle would add latency to
/// back-to-back requests on a reused connection) plus `SO_KEEPALIVE`. Failures
/// are logged, never fatal: the connection is still perfectly serviceable.
fn tune_tcp(stream: &tokio::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!("set_nodelay: {e}");
    }
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE)
        .with_interval(TCP_KEEPALIVE);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        tracing::debug!("set_tcp_keepalive: {e}");
    }
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

/// Connection timeouts, split the way a reverse proxy needs them.
///
/// hyper 1.x has a single `header_read_timeout`, and it runs both while a
/// request head is being read *and* while an idle keep-alive connection waits
/// for the next request. Driving it from `HeadersTimeoutSeconds` therefore closed
/// idle connections from Caddy after 10s instead of 60s — a reconnect per
/// request, and a close/reuse race that surfaces at the proxy as a 502.
///
/// So `KeepAliveTimeoutSeconds` owns hyper's timer (0 disables keep-alive
/// entirely), and `HeadersTimeoutSeconds` is enforced separately, by
/// `await_first_byte`, on a freshly accepted connection only. That bounds
/// slowloris on new connections, which is what it was there for.
///
/// The trade-off: a *partial* request head that stalls mid-way on an already
/// established keep-alive connection is bounded by `KeepAliveTimeoutSeconds`
/// (60s), not by `HeadersTimeoutSeconds` (10s). An attacker must complete one
/// full request before they can hold a socket for the longer window, and the
/// concurrency cost of that is the same as any idle keep-alive connection.
fn configure_http(builder: &mut auto::Builder<TokioExecutor>, cfg: &Config) {
    let keep_alive = cfg.keepalive_timeout_secs > 0;
    // With keep-alive off there is no idle wait to bound, so the headers timeout
    // is the only meaningful value for the single request head.
    let idle = if keep_alive {
        cfg.keepalive_timeout_secs
    } else {
        cfg.headers_timeout_secs.max(1)
    };
    builder
        .http1()
        .timer(TokioTimer::new())
        .keep_alive(keep_alive)
        // A client that pipelines back-to-back requests gets their responses
        // coalesced into one write instead of one syscall each.
        .pipeline_flush(true)
        .header_read_timeout(Some(Duration::from_secs(idle)));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_bind_addr_accepts_hosts_and_ips() {
        let addr = resolve_bind_addr("127.0.0.1:8081");
        assert_eq!(addr.port(), 8081);
        let addr = resolve_bind_addr("localhost:9090");
        assert_eq!(addr.port(), 9090);
    }

    #[test]
    fn configure_http_both_keepalive_modes() {
        let mut builder = auto::Builder::new(TokioExecutor::new());
        let mut cfg = Config::default();
        configure_http(&mut builder, &cfg);
        cfg.keepalive_timeout_secs = 0;
        configure_http(&mut builder, &cfg);
    }

    #[test]
    fn warn_helpers_only_log() {
        let mut cfg = Config::default();
        warn_on_dev_tokens(&cfg);
        cfg.user_token_hash = DEFAULT_USER_TOKEN_HASH.into();
        warn_on_dev_tokens(&cfg);

        // No URI host at all: nothing to compare.
        cfg.uri = String::new();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        // Upstream on this very address: warns.
        cfg.uri = "http://127.0.0.1:8081/sgx/certification/v4/".into();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
        // Unresolvable upstream host: no warning, no panic.
        cfg.uri = "https://nonexistent.invalid/sgx/".into();
        warn_on_self_upstream(&cfg, "127.0.0.1:8081".parse().unwrap());
    }

    #[tokio::test]
    async fn tune_tcp_and_acceptor_survive_a_live_socket() {
        use axum_server::accept::Accept;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });
        let (stream, _) = listener.accept().await.unwrap();
        tune_tcp(&stream);
        let (stream, _service) = TunedAcceptor.accept(stream, ()).await.unwrap();
        drop(stream);
        client.await.unwrap();
    }

    #[tokio::test]
    async fn await_first_byte_peeks_without_consuming() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // A client that sends a byte: true, and the byte is still there.
        // (Connect before accept: the backlog completes the handshake.)
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        client.write_all(b"G").await.unwrap();
        assert!(await_first_byte(&stream, Duration::from_secs(5)).await);
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"G", "peek must not consume the request head");

        // A client that hangs up immediately: false.
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        drop(client);
        assert!(!await_first_byte(&stream, Duration::from_secs(5)).await);

        // A silent client past the deadline: false.
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        assert!(!await_first_byte(&stream, Duration::from_millis(50)).await);

        // A zero deadline disables the check.
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        assert!(await_first_byte(&stream, Duration::ZERO).await);
    }

    #[tokio::test]
    async fn invalid_refresh_schedule_falls_back_to_the_default() {
        let cfg = Config::test_default();
        let cache = pccs_rs::cache::build_cache(&cfg).unwrap();
        // An unparseable schedule must not kill the task; it still computes a
        // next run from the daily-01:00 default.
        let handle = spawn_refresh_scheduler(cache, "not a cron".to_string());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!handle.is_finished());
        handle.abort();
    }
}
