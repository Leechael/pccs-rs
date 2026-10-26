//! Bounded, process-local Prometheus metrics. Recording uses only atomics and
//! fixed enum/route indexes: request data can never create a new time series.
use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use std::cell::RefCell;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

macro_rules! labels {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(usize)]
        pub enum $name { $($variant),+ }
        impl $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}

labels!(Kind {
    Pckcert => "pckcert", Pckcrl => "pckcrl", SgxTcb => "sgx_tcb", TdxTcb => "tdx_tcb",
    QeIdentity => "qe_identity", QveIdentity => "qve_identity", TdqeIdentity => "tdqe_identity",
    Rootcacrl => "rootcacrl", Crl => "crl", AmdKds => "amd_kds",
    NvidiaRim => "nvidia_rim", NvidiaOcsp => "nvidia_ocsp",
});
labels!(CacheResult {
    Hit => "hit", Miss => "miss", Expired => "expired", RecentFailure => "recent_failure",
    RecentNon200 => "recent_non200", LocalSelect => "local_select",
});
labels!(Upstream {
    IntelPcs => "intel_pcs", IntelCerts => "intel_certs", AmdKds => "amd_kds",
    NvidiaRim => "nvidia_rim", NvidiaOcsp => "nvidia_ocsp", NvidiaNras => "nvidia_nras", Pccs => "pccs",
});
labels!(UpstreamStatus {
    S200 => "200", S404 => "404", S429 => "429", S503 => "503", Other4xx => "other_4xx",
    Other5xx => "other_5xx", Timeout => "timeout", Error => "error", Other => "other",
});

impl UpstreamStatus {
    pub const fn from_status(status: u16) -> Self {
        match status {
            200 => Self::S200,
            404 => Self::S404,
            429 => Self::S429,
            503 => Self::S503,
            400..=499 => Self::Other4xx,
            500..=599 => Self::Other5xx,
            _ => Self::Other,
        }
    }
}

impl From<u16> for UpstreamStatus {
    fn from(status: u16) -> Self {
        Self::from_status(status)
    }
}

// Full MatchedPath templates, including nest prefixes. Keep in sync with
// routes/mod.rs and lib.rs. Never accept a raw path or wildcard suffix as a label.
const ROUTES: &[&str] = &[
    "/sgx/certification/v3/platforms",
    "/sgx/certification/v3/platformcollateral",
    "/sgx/certification/v3/refresh",
    "/sgx/certification/v3/appraisalpolicy",
    "/sgx/certification/v3/pckcert",
    "/sgx/certification/v3/pckcrl",
    "/sgx/certification/v3/tcb",
    "/sgx/certification/v3/qe/identity",
    "/sgx/certification/v3/qve/identity",
    "/sgx/certification/v3/rootcacrl",
    "/sgx/certification/v3/crl",
    "/sgx/certification/v4/platforms",
    "/sgx/certification/v4/platformcollateral",
    "/sgx/certification/v4/refresh",
    "/sgx/certification/v4/appraisalpolicy",
    "/sgx/certification/v4/pckcert",
    "/sgx/certification/v4/pckcrl",
    "/sgx/certification/v4/tcb",
    "/sgx/certification/v4/qe/identity",
    "/sgx/certification/v4/qve/identity",
    "/sgx/certification/v4/rootcacrl",
    "/sgx/certification/v4/crl",
    "/tdx/certification/v4/tcb",
    "/tdx/certification/v4/qe/identity",
    "/healthz/live",
    "/healthz/ready",
    "/healthz/startup",
    "/vcek/{*rest}",
    "/vlek/{*rest}",
    "/v1/rim/{*rest}",
    "/ocsp",
    "/nvidia/nras/attest/gpu",
    "/metrics",
    "unmatched",
];
const STATUS_CLASSES: &[&str] = &["2xx", "3xx", "4xx", "5xx", "other"];
const BUCKET_NANOS: [u64; 15] = [
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_500_000,
    5_000_000,
    10_000_000,
    50_000_000,
    100_000_000,
    500_000_000,
    1_000_000_000,
    5_000_000_000,
    30_000_000_000,
    60_000_000_000,
];
const BUCKET_LABELS: [&str; 16] = [
    "0.00005", "0.0001", "0.00025", "0.0005", "0.001", "0.0025", "0.005", "0.01", "0.05", "0.1",
    "0.5", "1", "5", "30", "60", "+Inf",
];

#[derive(Default)]
struct Histogram {
    // Disjoint buckets: exactly one bucket increment per observation.
    buckets: [AtomicU64; 16],
    sum_nanos: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn observe(&self, duration: Duration) {
        let bucket = BUCKET_NANOS.partition_point(|&bound| duration.as_nanos() > u128::from(bound));
        self.buckets[bucket].fetch_add(1, Relaxed);
        // Integer accumulation avoids a floating-point CAS loop on the hot path.
        // As with counters, sums wrap only after u64::MAX accumulated units
        // (about 584 years of aggregate observation time).
        self.sum_nanos.fetch_add(duration.as_nanos().min(u128::from(u64::MAX)) as u64, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, labels: &[(&str, &str)]) {
        if self.count.load(Relaxed) == 0 {
            return;
        }
        let mut cumulative = 0u64;
        for (bucket, le) in self.buckets.iter().zip(BUCKET_LABELS) {
            cumulative = cumulative.saturating_add(bucket.load(Relaxed));
            write!(out, "{name}_bucket").unwrap();
            render_labels(out, labels, Some(("le", le)));
            writeln!(out, " {cumulative}").unwrap();
        }
        write!(out, "{name}_sum").unwrap();
        render_labels(out, labels, None);
        writeln!(out, " {}", self.sum_nanos.load(Relaxed) as f64 / 1e9).unwrap();
        write!(out, "{name}_count").unwrap();
        render_labels(out, labels, None);
        // Deriving the snapshot count from the buckets keeps +Inf and count
        // identical even when observations race a scrape. Sum is approximate.
        writeln!(out, " {cumulative}").unwrap();
    }
}

fn render_labels(out: &mut String, labels: &[(&str, &str)], extra: Option<(&str, &str)>) {
    if labels.is_empty() && extra.is_none() {
        return;
    }
    out.push('{');
    for (i, (key, value)) in labels.iter().copied().chain(extra).enumerate() {
        if i != 0 {
            out.push(',');
        }
        write!(out, "{key}=\"").unwrap();
        for ch in value.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
    out.push('}');
}

fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    write!(out, "{name}").unwrap();
    render_labels(out, labels, None);
    writeln!(out, " {value}").unwrap();
}
fn family(out: &mut String, name: &str, ty: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}\n# TYPE {name} {ty}").unwrap();
}
fn route_index(route: &str) -> usize {
    ROUTES.iter().position(|&template| template == route).unwrap_or(ROUTES.len() - 1)
}
fn array<T: Default>(len: usize) -> Box<[T]> {
    std::iter::repeat_with(T::default).take(len).collect()
}

/// A registry with fixed storage and bounded labels. Construct once per process
/// and share by Arc; no locks or maps are used on recording paths.
pub struct Metrics {
    process_start: u64,
    cache: Box<[AtomicU64]>,
    store: Box<[Histogram]>,
    singleflight: Box<[Histogram]>,
    upstream: Box<[AtomicU64]>,
    upstream_duration: Box<[Histogram]>,
    throttled: Box<[AtomicU64]>,
    permit: Histogram,
    inflight: AtomicU64,
    refresh_runs: [AtomicU64; 2],
    refresh_items: Box<[AtomicU64]>,
    refresh_last_success: AtomicU64,
    refresh_last_duration: AtomicU64,
    http: Box<[AtomicU64]>,
    http_duration: Box<[Histogram]>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            process_start: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            cache: array(Kind::ALL.len() * CacheResult::ALL.len()),
            store: array(Kind::ALL.len()),
            singleflight: array(Kind::ALL.len()),
            upstream: array(Upstream::ALL.len() * UpstreamStatus::ALL.len()),
            upstream_duration: array(Upstream::ALL.len()),
            throttled: array(Upstream::ALL.len()),
            permit: Histogram::default(),
            inflight: AtomicU64::new(0),
            refresh_runs: Default::default(),
            refresh_items: array(Kind::ALL.len() * 2),
            refresh_last_success: AtomicU64::new(0),
            refresh_last_duration: AtomicU64::new(0),
            http: array(ROUTES.len() * STATUS_CLASSES.len()),
            http_duration: array(ROUTES.len()),
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cache_lookup(&self, kind: Kind, result: CacheResult) {
        self.cache[kind as usize * CacheResult::ALL.len() + result as usize].fetch_add(1, Relaxed);
        timing_cache(result);
    }
    pub fn store_read(&self, kind: Kind, duration: Duration) {
        self.store[kind as usize].observe(duration);
        timing_add(TimingStage::Store, duration);
    }
    pub fn singleflight_wait(&self, kind: Kind, duration: Duration) {
        self.singleflight[kind as usize].observe(duration);
        timing_add(TimingStage::Lock, duration);
    }
    pub fn upstream_attempt(&self, upstream: Upstream, status: UpstreamStatus, duration: Duration) {
        self.upstream[upstream as usize * UpstreamStatus::ALL.len() + status as usize]
            .fetch_add(1, Relaxed);
        self.upstream_duration[upstream as usize].observe(duration);
        timing_add(TimingStage::Upstream, duration);
    }
    pub fn upstream_throttled(&self, upstream: Upstream) {
        self.throttled[upstream as usize].fetch_add(1, Relaxed);
    }
    pub fn permit_wait(&self, duration: Duration) {
        self.permit.observe(duration);
        // Server-Timing describes the whole upstream client stage, while the
        // attempt histogram deliberately excludes semaphore waits and backoff.
        timing_add(TimingStage::Upstream, duration);
    }
    pub fn inflight_add(&self) {
        self.inflight.fetch_add(1, Relaxed);
    }
    pub fn inflight_sub(&self) {
        // Defensive saturation prevents an unmatched decrement exposing u64::MAX.
        let _ = self.inflight.fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_sub(1)));
    }
    pub fn refresh_run(&self, success: bool, duration: Duration) {
        self.refresh_runs[usize::from(success)].fetch_add(1, Relaxed);
        self.refresh_last_duration.store(duration.as_secs_f64().to_bits(), Relaxed);
        if success {
            let seconds =
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            self.refresh_last_success.store(seconds, Relaxed);
        }
    }
    pub fn refresh_item(&self, kind: Kind, success: bool) {
        self.refresh_items[kind as usize * 2 + usize::from(success)].fetch_add(1, Relaxed);
    }
    pub fn http_request(&self, route: &str, status: u16, duration: Duration) {
        let route = route_index(route);
        let class = match status {
            200..=299 => 0,
            300..=399 => 1,
            400..=499 => 2,
            500..=599 => 3,
            _ => 4,
        };
        self.http[route * STATUS_CLASSES.len() + class].fetch_add(1, Relaxed);
        self.http_duration[route].observe(duration);
    }

    /// Prometheus text exposition. Every fixed counter series is emitted even
    /// at zero, so scrapers observe its first increment. Empty histograms are
    /// omitted; possible labels and total storage are fixed at creation.
    pub fn render(&self) -> String {
        let mut out = String::new();
        family(
            &mut out,
            "process_start_time_seconds",
            "gauge",
            "Unix timestamp when this metrics registry started.",
        );
        sample(&mut out, "process_start_time_seconds", &[], self.process_start);
        family(&mut out, "pccs_build_info", "gauge", "Build version information.");
        sample(&mut out, "pccs_build_info", &[("version", env!("CARGO_PKG_VERSION"))], 1);
        family(
            &mut out,
            "pccs_cache_lookups_total",
            "counter",
            "Cache lookup outcomes: hit, miss and expired are mutually exclusive; hit rate is hit/(hit+miss+expired). recent_failure, recent_non200 and local_select are follow-up events after miss, excluded from that denominator.",
        );
        for &kind in Kind::ALL {
            for &result in CacheResult::ALL {
                let n = self.cache[kind as usize * CacheResult::ALL.len() + result as usize]
                    .load(Relaxed);
                sample(
                    &mut out,
                    "pccs_cache_lookups_total",
                    &[("kind", kind.as_str()), ("result", result.as_str())],
                    n,
                );
            }
        }
        for (name, help, histograms) in [
            (
                "pccs_store_read_duration_seconds",
                "RocksDB get latency in seconds, excluding deserialization (counted in Server-Timing app).",
                &self.store,
            ),
            (
                "pccs_cache_singleflight_wait_seconds",
                "Singleflight lock wait in seconds.",
                &self.singleflight,
            ),
        ] {
            family(&mut out, name, "histogram", help);
            for &kind in Kind::ALL {
                histograms[kind as usize].render(&mut out, name, &[("kind", kind.as_str())]);
            }
        }
        family(&mut out, "pccs_upstream_requests_total", "counter", "Upstream attempt outcomes.");
        for &upstream in Upstream::ALL {
            for &status in UpstreamStatus::ALL {
                let n = self.upstream
                    [upstream as usize * UpstreamStatus::ALL.len() + status as usize]
                    .load(Relaxed);
                sample(
                    &mut out,
                    "pccs_upstream_requests_total",
                    &[("upstream", upstream.as_str()), ("status", status.as_str())],
                    n,
                );
            }
        }
        family(
            &mut out,
            "pccs_upstream_attempt_duration_seconds",
            "histogram",
            "Upstream attempt latency in seconds.",
        );
        for &upstream in Upstream::ALL {
            self.upstream_duration[upstream as usize].render(
                &mut out,
                "pccs_upstream_attempt_duration_seconds",
                &[("upstream", upstream.as_str())],
            );
        }
        family(
            &mut out,
            "pccs_upstream_throttled_total",
            "counter",
            "Retries after upstream 429 or 503 responses.",
        );
        for &upstream in Upstream::ALL {
            let labels = [("upstream", upstream.as_str())];
            let n = self.throttled[upstream as usize].load(Relaxed);
            sample(&mut out, "pccs_upstream_throttled_total", &labels, n);
        }
        family(
            &mut out,
            "pccs_upstream_permit_wait_seconds",
            "histogram",
            "Upstream semaphore wait in seconds.",
        );
        self.permit.render(&mut out, "pccs_upstream_permit_wait_seconds", &[]);
        family(&mut out, "pccs_upstream_inflight", "gauge", "Currently active upstream attempts.");
        sample(&mut out, "pccs_upstream_inflight", &[], self.inflight.load(Relaxed));
        family(&mut out, "pccs_refresh_runs_total", "counter", "Completed refresh runs.");
        for (i, result) in ["error", "success"].iter().enumerate() {
            let n = self.refresh_runs[i].load(Relaxed);
            sample(&mut out, "pccs_refresh_runs_total", &[("result", result)], n);
        }
        family(&mut out, "pccs_refresh_items_total", "counter", "Refresh item outcomes.");
        for &kind in Kind::ALL {
            for (i, result) in ["error", "success"].iter().enumerate() {
                let n = self.refresh_items[kind as usize * 2 + i].load(Relaxed);
                sample(
                    &mut out,
                    "pccs_refresh_items_total",
                    &[("kind", kind.as_str()), ("result", result)],
                    n,
                );
            }
        }
        family(
            &mut out,
            "pccs_refresh_last_success_timestamp_seconds",
            "gauge",
            "Unix timestamp of the last successful refresh.",
        );
        sample(
            &mut out,
            "pccs_refresh_last_success_timestamp_seconds",
            &[],
            self.refresh_last_success.load(Relaxed),
        );
        family(
            &mut out,
            "pccs_refresh_last_duration_seconds",
            "gauge",
            "Duration of the last completed refresh in seconds.",
        );
        writeln!(
            out,
            "pccs_refresh_last_duration_seconds {}",
            f64::from_bits(self.refresh_last_duration.load(Relaxed))
        )
        .unwrap();
        family(
            &mut out,
            "pccs_http_requests_total",
            "counter",
            "HTTP responses by bounded route and status class.",
        );
        for (route, &template) in ROUTES.iter().enumerate() {
            for (class, &label) in STATUS_CLASSES.iter().enumerate() {
                let n = self.http[route * STATUS_CLASSES.len() + class].load(Relaxed);
                sample(
                    &mut out,
                    "pccs_http_requests_total",
                    &[("route", template), ("status_class", label)],
                    n,
                );
            }
        }
        family(
            &mut out,
            "pccs_http_request_duration_seconds",
            "histogram",
            "HTTP handler latency in seconds.",
        );
        for (route, &template) in ROUTES.iter().enumerate() {
            self.http_duration[route].render(
                &mut out,
                "pccs_http_request_duration_seconds",
                &[("route", template)],
            );
        }
        out
    }

    /// A separate, unauthenticated scrape router suitable for a private listener.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new().route(
            "/metrics",
            get(move || {
                let metrics = self.clone();
                async move {
                    (
                        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
                        metrics.render(),
                    )
                }
            }),
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TimingStage {
    Store,
    Lock,
    Upstream,
}

#[derive(Default)]
struct Timing {
    store: Duration,
    lock: Duration,
    upstream: Duration,
    cache: Option<CacheResult>,
}
tokio::task_local! { static TIMING: RefCell<Timing>; }

/// No-op when called outside an opted-in request (including background refresh).
pub fn timing_add(stage: TimingStage, duration: Duration) {
    let _ = TIMING.try_with(|timing| {
        let mut timing = timing.borrow_mut();
        let value = match stage {
            TimingStage::Store => &mut timing.store,
            TimingStage::Lock => &mut timing.lock,
            TimingStage::Upstream => &mut timing.upstream,
        };
        *value = value.saturating_add(duration);
    });
}
pub fn timing_cache(result: CacheResult) {
    let _ = TIMING.try_with(|timing| timing.borrow_mut().cache = Some(result));
}

/// Records bounded MatchedPath labels for all responses. Timing is opt-in and
/// never includes paths, query strings, collateral keys, or request identifiers.
pub async fn http_middleware(
    State((metrics, timing)): State<(Arc<Metrics>, bool)>,
    request: Request,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| route_index(path.as_str()))
        .unwrap_or(ROUTES.len() - 1);
    let start = Instant::now();
    let response = if timing {
        TIMING.scope(RefCell::new(Timing::default()), async {
            let mut response = next.run(request).await;
            let elapsed = start.elapsed();
            TIMING.with(|timing| {
                let timing = timing.borrow();
                let app = elapsed.saturating_sub(timing.store.saturating_add(timing.lock).saturating_add(timing.upstream));
                let value = format!(
                    "cache;desc={}, store;dur={:.3}, lock;dur={:.3}, upstream;dur={:.3}, app;dur={:.3}",
                    timing.cache.map(CacheResult::as_str).unwrap_or("none"),
                    timing.store.as_secs_f64() * 1000.0, timing.lock.as_secs_f64() * 1000.0,
                    timing.upstream.as_secs_f64() * 1000.0, app.as_secs_f64() * 1000.0,
                );
                if let Ok(value) = HeaderValue::from_str(&value) { response.headers_mut().insert("server-timing", value); }
            });
            response
        }).await
    } else {
        // Deliberately no task-local scope, timing state, or header formatting.
        next.run(request).await
    };
    metrics.http_request(ROUTES[route], response.status().as_u16(), start.elapsed());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::StatusCode;
    use tower::ServiceExt;

    #[test]
    fn fresh_registry_exposes_all_fixed_counter_series_at_zero() {
        let text = Metrics::new().render();
        assert!(text.contains(
            "pccs_upstream_requests_total{upstream=\"intel_pcs\",status=\"timeout\"} 0\n"
        ));
        let samples = parse_samples(&text);
        for (name, count) in [
            ("pccs_cache_lookups_total", Kind::ALL.len() * CacheResult::ALL.len()),
            ("pccs_upstream_requests_total", Upstream::ALL.len() * UpstreamStatus::ALL.len()),
            ("pccs_upstream_throttled_total", Upstream::ALL.len()),
            ("pccs_refresh_runs_total", 2),
            ("pccs_refresh_items_total", Kind::ALL.len() * 2),
            ("pccs_http_requests_total", ROUTES.len() * STATUS_CLASSES.len()),
        ] {
            let values: Vec<_> = samples.iter().filter(|(metric, _, _)| metric == name).collect();
            assert_eq!(
                values.len(),
                count,
                "{name}: every fixed combination must exist before its first increment"
            );
            assert!(values.iter().all(|(_, _, value)| *value == 0.0), "{name}");
        }
    }

    #[tokio::test]
    async fn registered_route_templates_match_the_real_app_without_drift() {
        use crate::config::{CacheMode, Config};
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let apps: Vec<_> = [3, 4]
            .into_iter()
            .zip(&dirs)
            .map(|(version, dir)| {
                let mut cfg = Config::test_default();
                cfg.uri = format!("http://127.0.0.1:1/sgx/certification/v{version}/");
                cfg.cache_mode = CacheMode::Offline;
                cfg.no_seed = true;
                cfg.db_path = dir.path().join("db");
                let state = crate::app_state(cfg);
                let metrics = state.cache.store.metrics.clone();
                (crate::create_app(state), metrics)
            })
            .collect();
        for &template in ROUTES.iter().filter(|&&route| route != "unmatched" && route != "/metrics")
        {
            let (app, metrics) =
                &apps[usize::from(!template.starts_with("/sgx/certification/v3/"))];
            let concrete = match template {
                "/vcek/{*rest}" => "/vcek/v1/Milan/0123456789abcdef",
                "/vlek/{*rest}" => "/vlek/v1/Genoa/cert_chain",
                "/v1/rim/{*rest}" => "/v1/rim/synthetic-rim",
                path => path,
            };
            assert!(!concrete.contains('{'), "add a concrete test path for {template}");
            let method = if template.ends_with("/platformcollateral") {
                "PUT"
            } else if ["/ocsp", "/nvidia/nras/attest/gpu"].contains(&template) {
                "POST"
            } else {
                "GET"
            };
            let response = app
                .clone()
                .oneshot(
                    Request::builder().method(method).uri(concrete).body(Body::empty()).unwrap(),
                )
                .await
                .unwrap();
            let class = format!("{}xx", response.status().as_u16() / 100);
            let text = metrics.render();
            assert!(
                text.lines().any(|line| line
                    == format!(
                "pccs_http_requests_total{{route=\"{template}\",status_class=\"{class}\"}} 1"
            )),
                "{method} {concrete} must retain MatchedPath {template}: {text}"
            );
            assert!(text.lines().filter(|line| line.starts_with("pccs_http_requests_total{route=\"unmatched\","))
                .all(|line| line.ends_with(" 0")), "registered route fell back to unmatched: {template}");
        }
    }

    #[test]
    fn histogram_buckets_are_inclusive_and_cumulative() {
        let metrics = Metrics::new();
        for duration in [
            Duration::from_micros(50),
            Duration::from_micros(51),
            Duration::from_millis(1),
            Duration::from_secs(60),
            Duration::from_secs(61),
        ] {
            metrics.store_read(Kind::Pckcert, duration);
        }
        let text = metrics.render();
        let buckets: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("pccs_store_read_duration_seconds_bucket"))
            .collect();
        assert_eq!(
            buckets,
            vec![
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.00005\"} 1",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.0001\"} 2",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.00025\"} 2",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.0005\"} 2",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.001\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.0025\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.005\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.01\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.05\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.1\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"0.5\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"1\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"5\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"30\"} 3",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"60\"} 4",
                "pccs_store_read_duration_seconds_bucket{kind=\"pckcert\",le=\"+Inf\"} 5",
            ]
        );
        assert!(text.contains("pccs_store_read_duration_seconds_count{kind=\"pckcert\"} 5\n"));
        let sum = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("pccs_store_read_duration_seconds_sum{kind=\"pckcert\"} ")
            })
            .unwrap()
            .parse::<f64>()
            .unwrap();
        assert!((sum - 121.001101).abs() < 1e-10);
    }

    // A deliberately independent, small exposition reader. It consumes quoted
    // label strings (including escapes), not the renderer's label helpers, and
    // rejects duplicate samples, malformed names, escapes, or numeric values.
    type ParsedSample = (String, Vec<(String, String)>, f64);

    fn parse_samples(text: &str) -> Vec<ParsedSample> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut families = HashSet::new();
        let mut current_family = None;
        let mut samples = Vec::new();
        for line in text.lines().filter(|line| !line.is_empty()) {
            if let Some(definition) = line.strip_prefix("# TYPE ") {
                let (name, ty) = definition.split_once(' ').expect("family type");
                assert!(["counter", "gauge", "histogram"].contains(&ty));
                assert!(families.insert(name), "duplicate family");
                current_family = Some(name);
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            let mut chars = line.chars().peekable();
            let name: String = std::iter::from_fn(|| {
                chars.next_if(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == ':')
            })
            .collect();
            assert!(name.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_' || ch == ':'));
            if let Some(family) = current_family {
                assert!(
                    name == family
                        || ["_bucket", "_sum", "_count"]
                            .iter()
                            .any(|suffix| name.strip_suffix(suffix) == Some(family)),
                    "interleaved family: {name}"
                );
            }
            let mut labels = Vec::new();
            if chars.next_if_eq(&'{').is_some() {
                loop {
                    let key: String = std::iter::from_fn(|| {
                        chars.next_if(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                    })
                    .collect();
                    assert!(!key.is_empty());
                    assert_eq!(chars.next(), Some('='));
                    assert_eq!(chars.next(), Some('"'));
                    let mut value = String::new();
                    loop {
                        match chars.next().expect("unterminated label") {
                            '"' => break,
                            '\\' => value.push(match chars.next().expect("unterminated escape") {
                                'n' => '\n',
                                '\\' => '\\',
                                '"' => '"',
                                other => panic!("invalid escape: {other}"),
                            }),
                            '\n' => panic!("unescaped newline"),
                            ch => value.push(ch),
                        }
                    }
                    assert!(!labels.iter().any(|(prior, _)| prior == &key));
                    labels.push((key, value));
                    match chars.next() {
                        Some('}') => break,
                        Some(',') => {}
                        other => panic!("invalid label separator: {other:?}"),
                    }
                }
            }
            assert_eq!(chars.next(), Some(' '));
            let value = chars.collect::<String>().parse::<f64>().expect("numeric sample");
            assert!(value.is_finite());
            assert!(seen.insert((name.clone(), labels.clone())), "duplicate sample");
            samples.push((name, labels, value));
        }
        samples
    }

    #[test]
    fn exposition_and_label_escaping_parse_independently() {
        let mut escaped = String::from("test_metric");
        render_labels(&mut escaped, &[("label", "quote\" backslash\\ newline\n unicodeé")], None);
        escaped.push_str(" 1\n");
        assert_eq!(
            parse_samples(&escaped),
            vec![(
                "test_metric".into(),
                vec![("label".into(), "quote\" backslash\\ newline\n unicodeé".into())],
                1.0
            )]
        );
        let metrics = Metrics::new();
        for &kind in Kind::ALL {
            for &result in CacheResult::ALL {
                metrics.cache_lookup(kind, result);
            }
            metrics.store_read(kind, Duration::ZERO);
            metrics.singleflight_wait(kind, Duration::from_secs(1));
            metrics.refresh_item(kind, true);
            metrics.refresh_item(kind, false);
        }
        for &upstream in Upstream::ALL {
            for &status in UpstreamStatus::ALL {
                metrics.upstream_attempt(upstream, status, Duration::from_millis(5));
            }
            metrics.upstream_throttled(upstream);
        }
        metrics.permit_wait(Duration::ZERO);
        metrics.refresh_run(true, Duration::from_millis(250));
        for route in ROUTES {
            metrics.http_request(route, 200, Duration::from_micros(50));
        }
        let samples = parse_samples(&metrics.render());
        assert!(samples.len() > 1000);
    }

    #[test]
    fn http_labels_are_bounded_and_unknown_routes_are_unmatched() {
        let metrics = Metrics::new();
        for id in 0..1000 {
            metrics.http_request(
                &format!("/vcek/secret-chip-{id}"),
                400 + id % 100,
                Duration::ZERO,
            );
        }
        metrics.http_request("/vcek/{*rest}", 201, Duration::from_millis(1));
        metrics.http_request("/sgx/certification/v4/pckcert?qeid=SECRET", 500, Duration::ZERO);
        let text = metrics.render();
        assert!(text
            .contains("pccs_http_requests_total{route=\"unmatched\",status_class=\"4xx\"} 1000\n"));
        assert!(
            text.contains("pccs_http_requests_total{route=\"unmatched\",status_class=\"5xx\"} 1\n")
        );
        assert!(text.contains(
            "pccs_http_requests_total{route=\"/vcek/{*rest}\",status_class=\"2xx\"} 1\n"
        ));
        assert!(
            text.contains("pccs_http_request_duration_seconds_count{route=\"unmatched\"} 1001\n")
        );
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("secret-chip"));
        assert_eq!(
            text.lines().filter(|line| line.starts_with("pccs_http_requests_total{")).count(),
            ROUTES.len() * STATUS_CLASSES.len()
        );
        assert_eq!(
            text.lines()
                .filter(
                    |line| line.starts_with("pccs_http_requests_total{") && !line.ends_with(" 0")
                )
                .count(),
            3
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("pccs_http_request_duration_seconds_count{"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn timing_is_opt_in_and_uses_latest_cache_result_without_keys() {
        for enabled in [false, true] {
            let metrics = Arc::new(Metrics::new());
            let record = metrics.clone();
            let app = Router::new()
                .route(
                    "/vcek/{*rest}",
                    get(move || {
                        let record = record.clone();
                        async move {
                            assert_eq!(TIMING.try_with(|_| ()).is_ok(), enabled);
                            timing_cache(CacheResult::Miss);
                            timing_cache(CacheResult::Hit);
                            timing_add(TimingStage::Store, Duration::from_micros(1500));
                            timing_add(TimingStage::Lock, Duration::from_micros(250));
                            timing_add(TimingStage::Upstream, Duration::from_millis(2));
                            record.permit_wait(Duration::from_millis(3));
                            "ok"
                        }
                    }),
                )
                .layer(axum::middleware::from_fn_with_state(
                    (metrics.clone(), enabled),
                    http_middleware,
                ));
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/vcek/SECRET-CHIP?token=SECRET-TOKEN")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            if enabled {
                let header = response.headers()["server-timing"].to_str().unwrap();
                assert!(header.starts_with(
                    "cache;desc=hit, store;dur=1.500, lock;dur=0.250, upstream;dur=5.000, app;dur="
                ));
                assert!(!header.contains("SECRET"));
            } else {
                assert!(!response.headers().contains_key("server-timing"));
            }
            assert!(TIMING.try_with(|_| ()).is_err());
            let text = metrics.render();
            assert!(text.contains(
                "pccs_http_requests_total{route=\"/vcek/{*rest}\",status_class=\"2xx\"} 1\n"
            ));
            assert!(!text.contains("SECRET"));
        }
        // Helpers are harmless in non-HTTP/background tasks.
        timing_add(TimingStage::Store, Duration::from_secs(1));
        timing_cache(CacheResult::Expired);
    }

    #[tokio::test]
    async fn scrape_router_exposes_prometheus_content_type() {
        let metrics = Arc::new(Metrics::new());
        metrics.cache_lookup(Kind::SgxTcb, CacheResult::Miss);
        let response = metrics
            .router()
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let text =
            String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await.unwrap().to_vec())
                .unwrap();
        assert!(text.contains("pccs_cache_lookups_total{kind=\"sgx_tcb\",result=\"miss\"} 1\n"));
        parse_samples(&text);
    }

    #[test]
    fn refresh_gauges_and_upstream_statuses_are_bounded() {
        let metrics = Metrics::new();
        metrics.inflight_add();
        metrics.inflight_add();
        metrics.inflight_sub();
        assert!(metrics.render().contains("pccs_upstream_inflight 1\n"));
        metrics.inflight_sub();
        metrics.inflight_sub();
        assert!(metrics.render().contains("pccs_upstream_inflight 0\n"));
        metrics.refresh_run(true, Duration::from_millis(250));
        let success = metrics
            .render()
            .lines()
            .find(|line| line.starts_with("pccs_refresh_last_success_timestamp_seconds "))
            .unwrap()
            .to_owned();
        assert_ne!(success, "pccs_refresh_last_success_timestamp_seconds 0");
        metrics.refresh_run(false, Duration::from_millis(125));
        let text = metrics.render();
        assert!(text.lines().any(|line| line == success));
        assert!(text.contains("pccs_refresh_last_duration_seconds 0.125\n"));
        assert!(text.contains("pccs_refresh_runs_total{result=\"error\"} 1\n"));
        assert!(text.contains("pccs_refresh_runs_total{result=\"success\"} 1\n"));
        assert_eq!(UpstreamStatus::from_status(200), UpstreamStatus::S200);
        assert_eq!(UpstreamStatus::from_status(404), UpstreamStatus::S404);
        assert_eq!(UpstreamStatus::from_status(429), UpstreamStatus::S429);
        assert_eq!(UpstreamStatus::from_status(503), UpstreamStatus::S503);
        assert_eq!(UpstreamStatus::from_status(401), UpstreamStatus::Other4xx);
        assert_eq!(UpstreamStatus::from_status(502), UpstreamStatus::Other5xx);
        assert_eq!(UpstreamStatus::from_status(201), UpstreamStatus::Other);
    }

    #[test]
    fn process_start_and_build_info_are_stable_across_scrapes() {
        let metrics = Metrics::new();
        let first = metrics.render();
        let start =
            first.lines().find(|line| line.starts_with("process_start_time_seconds ")).unwrap();
        assert_ne!(start, "process_start_time_seconds 0");
        assert!(first.contains(&format!(
            "pccs_build_info{{version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        )));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(metrics.render().lines().any(|line| line == start));
    }

    #[test]
    fn concurrent_recording_does_not_lose_counts() {
        let metrics = Arc::new(Metrics::new());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let metrics = metrics.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        metrics.cache_lookup(Kind::Pckcert, CacheResult::Hit);
                        metrics.store_read(Kind::Pckcert, Duration::from_millis(1));
                    }
                });
            }
        });
        let text = metrics.render();
        assert!(text.contains("pccs_cache_lookups_total{kind=\"pckcert\",result=\"hit\"} 8000\n"));
        assert!(text.contains("pccs_store_read_duration_seconds_count{kind=\"pckcert\"} 8000\n"));
        let sum = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("pccs_store_read_duration_seconds_sum{kind=\"pckcert\"} ")
            })
            .unwrap()
            .parse::<f64>()
            .unwrap();
        assert!((sum - 8.0).abs() < 1e-9);
    }
}
