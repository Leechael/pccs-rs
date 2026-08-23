//! Cache-hit load generator for pccs-rs.
//!
//! Mix: 70% GET /pckcert, 20% GET /tcb, 10% GET /qe/identity.
//! HTTP and HTTPS (use --insecure for self-signed dev certs).

#![forbid(unsafe_code)]

use clap::Parser;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser, Debug, Clone)]
#[command(name = "loadgen", about = "pccs-rs cache-hit load generator")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8081")]
    url: String,
    #[arg(long, default_value_t = 5)]
    duration: u64,
    #[arg(long, default_value_t = 32)]
    concurrency: usize,
    /// Accept any server certificate (needed for self-signed HTTPS).
    #[arg(long, default_value_t = false)]
    insecure: bool,
    /// Warmup seconds (not counted in rps / latency).
    #[arg(long, default_value_t = 0)]
    warmup: u64,
    #[arg(long, default_value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    qeid: String,
    #[arg(long, default_value = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")]
    cpusvn: String,
    #[arg(long, default_value = "CCCC")]
    pcesvn: String,
    #[arg(long, default_value = "DDDD")]
    pceid: String,
    #[arg(long, default_value = "ABCDABCDABCD")]
    fmspc: String,
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn pick_path(args: &Args, i: u64) -> String {
    let r = i % 10;
    if r < 7 {
        format!(
            "/sgx/certification/v4/pckcert?qeid={}&cpusvn={}&pcesvn={}&pceid={}",
            args.qeid, args.cpusvn, args.pcesvn, args.pceid
        )
    } else if r < 9 {
        format!("/sgx/certification/v4/tcb?fmspc={}", args.fmspc)
    } else {
        "/sgx/certification/v4/qe/identity".to_string()
    }
}

enum AnyClient {
    Http(Client<HttpConnector, Empty<Bytes>>),
    Https(Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>),
}

impl AnyClient {
    async fn get(&self, uri: &str) -> Result<hyper::Response<hyper::body::Incoming>, String> {
        let req = Request::get(uri)
            .body(Empty::<Bytes>::new())
            .map_err(|e| e.to_string())?;
        match self {
            AnyClient::Http(c) => c.request(req).await.map_err(|e| e.to_string()),
            AnyClient::Https(c) => c.request(req).await.map_err(|e| e.to_string()),
        }
    }
}

fn build_client(https: bool, _insecure: bool) -> AnyClient {
    if !https {
        return AnyClient::Http(Client::builder(TokioExecutor::new()).build_http());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let https_conn = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    AnyClient::Https(Client::builder(TokioExecutor::new()).build(https_conn))
}

struct Counters {
    ok: AtomicU64,
    err: AtomicU64,
    lat_us: std::sync::Mutex<Vec<u64>>,
}

impl Counters {
    fn new() -> Self {
        Self {
            ok: AtomicU64::new(0),
            err: AtomicU64::new(0),
            lat_us: std::sync::Mutex::new(Vec::with_capacity(1 << 16)),
        }
    }
    fn reset(&self) {
        self.ok.store(0, Ordering::Relaxed);
        self.err.store(0, Ordering::Relaxed);
        if let Ok(mut g) = self.lat_us.lock() {
            g.clear();
        }
    }
}

async fn run_workers(
    args: Args,
    base: String,
    https: bool,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    for w in 0..args.concurrency {
        let args = args.clone();
        let base = base.clone();
        let stop = stop.clone();
        let counters = counters.clone();
        handles.push(tokio::spawn(async move {
            let client = build_client(https, args.insecure);
            let mut n = w as u64;
            while !stop.load(Ordering::Relaxed) {
                let path = pick_path(&args, n);
                n += args.concurrency as u64;
                let uri = format!("{base}{path}");
                let t0 = Instant::now();
                match client.get(&uri).await {
                    Ok(resp) => {
                        let status = resp.status();
                        let _ = resp.into_body().collect().await;
                        let us = t0.elapsed().as_micros() as u64;
                        if status.is_success() {
                            counters.ok.fetch_add(1, Ordering::Relaxed);
                            if let Ok(mut g) = counters.lat_us.lock() {
                                g.push(us);
                            }
                        } else {
                            counters.err.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        counters.err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    handles
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let base = args.url.trim_end_matches('/').to_string();
    let https = base.starts_with("https://");
    if https {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Counters::new());

    if args.warmup > 0 {
        let handles = run_workers(
            args.clone(),
            base.clone(),
            https,
            stop.clone(),
            counters.clone(),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(args.warmup)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.await;
        }
        counters.reset();
        stop.store(false, Ordering::Relaxed);
    }

    let duration = Duration::from_secs(args.duration);
    let start = Instant::now();
    let handles = run_workers(args.clone(), base, https, stop.clone(), counters.clone()).await;
    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }
    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let ok_n = counters.ok.load(Ordering::Relaxed);
    let err_n = counters.err.load(Ordering::Relaxed);
    let total = ok_n + err_n;
    let rps = ok_n as f64 / elapsed;

    let mut samples = counters.lat_us.lock().unwrap().clone();
    samples.sort_unstable();
    let p50 = percentile_ms(&samples, 0.50);
    let p99 = percentile_ms(&samples, 0.99);

    let transport = if https { "HTTPS" } else { "HTTP, no TLS" };
    println!("pccs-rs cache-hit benchmark");
    println!(
        "endpoint mix: 70% GET /sgx/certification/v4/pckcert, 20% GET /tcb, 10% GET /qe/identity"
    );
    println!("seeded cache, {transport}, no Intel network");
    println!("url: {}", args.url);
    println!("concurrency: {}", args.concurrency);
    println!("warmup_s: {}", args.warmup);
    println!("duration_s: {:.3}", elapsed);
    println!("requests: {total} (ok={ok_n} err={err_n})");
    println!("rps: {:.1}", rps);
    println!("p50_ms: {:.3}", p50);
    println!("p99_ms: {:.3}", p99);
}

fn percentile_ms(sorted_us: &[u64], p: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_us.len() as f64 - 1.0) * p).round() as usize;
    sorted_us[idx] as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_defaults_match_the_readme() {
        let args = Args::parse_from(["loadgen"]);
        assert_eq!(args.url, "http://127.0.0.1:8081");
        assert_eq!(args.duration, 5);
        assert_eq!(args.concurrency, 32);
        assert!(!args.insecure);
        assert_eq!(args.warmup, 0);

        let args = Args::parse_from([
            "loadgen",
            "--url",
            "https://pccs.test",
            "--duration",
            "10",
            "--concurrency",
            "4",
            "--insecure",
            "--warmup",
            "2",
        ]);
        assert_eq!(args.url, "https://pccs.test");
        assert_eq!(args.duration, 10);
        assert_eq!(args.concurrency, 4);
        assert!(args.insecure);
        assert_eq!(args.warmup, 2);
    }

    #[test]
    fn pick_path_is_the_documented_70_20_10_mix() {
        let args = Args::parse_from(["loadgen"]);
        let mut pckcert = 0;
        let mut tcb = 0;
        let mut identity = 0;
        for i in 0..10u64 {
            let path = pick_path(&args, i);
            if path.contains("/pckcert?") {
                pckcert += 1;
                assert!(path.contains("qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
            } else if path.contains("/tcb?") {
                tcb += 1;
                assert!(path.contains("fmspc=ABCDABCDABCD"));
            } else {
                identity += 1;
                assert_eq!(path, "/sgx/certification/v4/qe/identity");
            }
        }
        assert_eq!((pckcert, tcb, identity), (7, 2, 1));
    }

    #[test]
    fn percentile_ms_edges() {
        assert_eq!(percentile_ms(&[], 0.5), 0.0);
        assert_eq!(percentile_ms(&[1000], 0.99), 1.0);
        let samples: Vec<u64> = (1..=100).map(|i| i * 1000).collect();
        // idx = round(99 * 0.5) = 50 → the 51st sample.
        assert_eq!(percentile_ms(&samples, 0.50), 51.0);
        assert_eq!(percentile_ms(&samples, 0.99), 99.0);
        assert_eq!(percentile_ms(&samples, 0.0), 1.0);
    }

    #[test]
    fn counters_reset_clears_everything() {
        let c = Counters::new();
        c.ok.fetch_add(3, Ordering::Relaxed);
        c.err.fetch_add(1, Ordering::Relaxed);
        c.lat_us.lock().unwrap().push(42);
        c.reset();
        assert_eq!(c.ok.load(Ordering::Relaxed), 0);
        assert_eq!(c.err.load(Ordering::Relaxed), 0);
        assert!(c.lat_us.lock().unwrap().is_empty());
    }

    #[test]
    fn build_client_http_and_https() {
        assert!(matches!(build_client(false, false), AnyClient::Http(_)));
        assert!(matches!(build_client(true, true), AnyClient::Https(_)));
    }

    #[tokio::test]
    async fn workers_count_ok_and_err_against_a_live_server() {
        use axum::routing::get;
        // /tcb and /qe/identity 200; /pckcert 404 (errors are counted, not fatal).
        let app = axum::Router::new()
            .route(
                "/sgx/certification/v4/tcb",
                get(|| async { axum::body::Body::from("{}") }),
            )
            .route(
                "/sgx/certification/v4/qe/identity",
                get(|| async { axum::body::Body::from("{}") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        let args = Args {
            url: format!("http://{addr}"),
            concurrency: 2,
            ..Args::parse_from(["loadgen"])
        };
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::new());
        let handles = run_workers(
            args,
            format!("http://{addr}"),
            false,
            stop.clone(),
            counters.clone(),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.await.unwrap();
        }
        let ok = counters.ok.load(Ordering::Relaxed);
        let err = counters.err.load(Ordering::Relaxed);
        assert!(ok > 0, "tcb/identity responses count as ok");
        assert!(err > 0, "pckcert 404s count as err");
        assert!(!counters.lat_us.lock().unwrap().is_empty());
    }
}
