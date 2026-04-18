use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

use goodgirls_registry::{atproto, db, routes, state::AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `.env` is optional — the deployed unit loads the same keys via
    // systemd's EnvironmentFile, but locally dotenvy is convenient.
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let database_url = require_env("DATABASE_URL")?;
    let admin_key_hash = require_env("ADMIN_KEY_HASH")?;
    let base_domain = require_env("BASE_DOMAIN")?;
    let listen_addr = require_env("LISTEN_ADDR")?;
    let decoy_path = require_env("DECOY_PATH")?;

    if !decoy_path.starts_with('/') {
        return Err("DECOY_PATH must start with '/'".into());
    }

    tracing::info!(database_url, %base_domain, %listen_addr, "starting goodgirls-registry");

    let pool = db::connect(&database_url).await?;
    db::migrate(&pool).await?;

    // Sessions are single-slot by design; any row surviving a restart is
    // dead weight. Wipe on boot (D8).
    let _ = db::delete_all_sessions(&pool).await;

    let atproto = atproto::Client::new()?;

    let state = AppState {
        pool,
        atproto,
        admin_key_hash,
        base_domain,
        decoy_path,
    };

    let app = routes::build(state).layer(tower_http::trace::TraceLayer::new_for_http());

    let addr: SocketAddr = listen_addr.parse()?;
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn require_env(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("{key} is required"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        sig.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("ctrl-c received, shutting down"),
        _ = terminate => tracing::info!("SIGTERM received, shutting down"),
    }
}
