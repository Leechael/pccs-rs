//! Plain-HTTP accept loop, connection timeouts, and a short drain before close.
//!
//! Tests bind a real listener through `serve_http` so request-receive behaviour
//! (header timeout, unexpected bodies, unread-body close) is exercised on the
//! same path the binary uses.

use crate::config::Config;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// How long in-flight requests get to finish after SIGINT / SIGTERM.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// TCP keepalive on accepted connections. Long-lived keep-alive connections from
/// the reverse proxy would otherwise be indistinguishable from a proxy that died
/// without a FIN, and idle NAT / load-balancer state can be dropped underneath
/// them. Not configurable on purpose: it is a transport-level liveness probe,
/// unrelated to the HTTP keep-alive idle timeout.
pub const TCP_KEEPALIVE: Duration = Duration::from_secs(60);

/// After an early reject, keep reading leftover request bytes for this long so
/// the peer can finish receiving the error response instead of seeing a reset.
pub const DRAIN_GRACE: Duration = Duration::from_secs(3);

/// Plain HTTP with the same connection timeouts as the binary, plus a drain
/// grace on close. `shutdown` ends the accept loop (SIGINT / SIGTERM in the
/// binary; a test oneshot or `pending` plus abort in tests).
pub async fn serve_http(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    cfg: &Config,
    shutdown: impl Future<Output = ()>,
) {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_http(&mut builder, cfg);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
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
                    let ready = await_first_byte(&stream, first_byte).await;
                    if ready {
                        let _ = tx.send(stream);
                    }
                });
            }
            Some(stream) = ready_rx.recv() => {
                let service = TowerToHyperService::new(app.clone());
                let io = DrainGraceIo::new(stream, DRAIN_GRACE);
                let conn = builder
                    .serve_connection_with_upgrades(TokioIo::new(io), service)
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
pub async fn await_first_byte(stream: &tokio::net::TcpStream, timeout: Duration) -> bool {
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
pub fn tune_tcp(stream: &tokio::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!("set_nodelay: {e}");
    }
    let keepalive =
        socket2::TcpKeepalive::new().with_time(TCP_KEEPALIVE).with_interval(TCP_KEEPALIVE);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        tracing::debug!("set_tcp_keepalive: {e}");
    }
}

/// Connection timeouts, split the way a reverse proxy needs them.
///
/// hyper 1.x has a single `header_read_timeout`, and it runs both while a
/// request head is being read *and* while an idle keep-alive connection waits
/// for the next request. Driving it from `HeadersTimeoutSeconds` therefore closed
/// idle connections from Caddy after the headers timeout instead of the
/// keep-alive idle timeout — a reconnect per request, and a close/reuse race
/// that surfaces at the proxy as a 502.
///
/// So `KeepAliveTimeoutSeconds` owns hyper's timer (0 disables keep-alive
/// entirely), and `HeadersTimeoutSeconds` is enforced separately, by
/// `await_first_byte`, on a freshly accepted connection only. That bounds
/// slowloris on new connections, which is what it was there for.
///
/// The trade-off: a *partial* request head that stalls mid-way on an already
/// established keep-alive connection is bounded by `KeepAliveTimeoutSeconds`,
/// not by `HeadersTimeoutSeconds`. An attacker must complete one full request
/// before they can hold a socket for the longer window, and the concurrency
/// cost of that is the same as any idle keep-alive connection.
pub fn configure_http(builder: &mut auto::Builder<TokioExecutor>, cfg: &Config) {
    let keep_alive = cfg.keepalive_timeout_secs > 0;
    // With keep-alive off there is no idle wait to bound, so the headers timeout
    // is the only meaningful value for the single request head.
    let idle =
        if keep_alive { cfg.keepalive_timeout_secs } else { cfg.headers_timeout_secs.max(1) };
    builder
        .http1()
        .timer(TokioTimer::new())
        .keep_alive(keep_alive)
        // A client that pipelines back-to-back requests gets their responses
        // coalesced into one write instead of one syscall each.
        .pipeline_flush(true)
        .header_read_timeout(Some(Duration::from_secs(idle)));
}

/// Forwards I/O to a `TcpStream`. On drop, shuts the write half and reads any
/// leftover request bytes for `grace` so a client still sending a body can
/// receive the error response instead of a TCP reset.
pub struct DrainGraceIo {
    stream: Option<tokio::net::TcpStream>,
    grace: Duration,
}

impl DrainGraceIo {
    pub fn new(stream: tokio::net::TcpStream, grace: Duration) -> Self {
        Self { stream: Some(stream), grace }
    }

    fn stream_mut(self: Pin<&mut Self>) -> Pin<&mut tokio::net::TcpStream> {
        let this = self.get_mut();
        Pin::new(this.stream.as_mut().expect("stream already taken"))
    }
}

impl Drop for DrainGraceIo {
    fn drop(&mut self) {
        let Some(stream) = self.stream.take() else {
            return;
        };
        let grace = self.grace;
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            drain_and_close(stream, grace).await;
        });
    }
}

async fn drain_and_close(mut stream: tokio::net::TcpStream, grace: Duration) {
    let _ = stream.shutdown().await;
    let drain = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(grace, drain).await;
}

impl AsyncRead for DrainGraceIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.stream_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for DrainGraceIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.stream_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.stream_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.stream_mut().poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn configure_http_both_keepalive_modes() {
        let mut builder = auto::Builder::new(TokioExecutor::new());
        let mut cfg = Config::default();
        configure_http(&mut builder, &cfg);
        cfg.keepalive_timeout_secs = 0;
        configure_http(&mut builder, &cfg);
    }

    #[tokio::test]
    async fn await_first_byte_peeks_without_consuming() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        client.write_all(b"G").await.unwrap();
        let ready = await_first_byte(&stream, Duration::from_secs(5)).await;
        assert!(ready);
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"G", "peek must not consume the request head");

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        drop(client);
        let ready = await_first_byte(&stream, Duration::from_secs(5)).await;
        assert!(!ready);

        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let ready = await_first_byte(&stream, Duration::from_millis(50)).await;
        assert!(!ready);

        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let ready = await_first_byte(&stream, Duration::ZERO).await;
        assert!(ready);
    }

    #[tokio::test]
    async fn tune_tcp_survives_a_live_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let (stream, _) = listener.accept().await.unwrap();
        tune_tcp(&stream);
        drop(stream);
        client.await.unwrap();
    }

    #[tokio::test]
    async fn drain_grace_io_drop_does_not_panic() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let (stream, _) = listener.accept().await.unwrap();
        drop(DrainGraceIo::new(stream, Duration::from_millis(20)));
        client.await.unwrap();
    }
}
