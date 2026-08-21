use clap::Parser;
use pccs_rs::config::{Cli, Config};
use pccs_rs::{app_state, create_app};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let cfg = Config::from(cli);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    run(cfg).await;
}

async fn run(cfg: Config) {
    let addr: SocketAddr = cfg
        .bind_addr()
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], cfg.port)));

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

    let state = app_state(cfg.clone());
    spawn_refresh_scheduler(state.cache.clone(), cfg.refresh_schedule.clone());
    let app = create_app(state);

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
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service())
            .await
            .expect("https server");
    } else {
        tracing::info!("HTTP Server is running on: http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| {
                eprintln!("bind {addr}: {e}");
                std::process::exit(1);
            });
        axum::serve(listener, app).await.expect("http server");
    }
}

fn spawn_refresh_scheduler(cache: Arc<pccs_rs::cache::Cache>, schedule: String) {
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
                break;
            };
            let wait = (next - now).to_std().unwrap_or(std::time::Duration::from_secs(60));
            tracing::info!("next scheduled refresh at {next} (in {wait:?})");
            tokio::time::sleep(wait).await;
            match cache.refresh(None, None).await {
                Ok(()) => tracing::info!("scheduled refresh complete"),
                Err(e) => tracing::warn!("scheduled refresh: {e}"),
            }
        }
    });
}
