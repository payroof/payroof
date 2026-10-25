use payroof::{App, config::Config};
use std::sync::atomic::Ordering;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("healthcheck") {
        return healthcheck(&args.next().unwrap_or("http://127.0.0.1:8080/readyz".into()));
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let path = first.unwrap_or_else(|| "config/payroof.local.toml".into());
    let app = payroof::startup(Config::load(&path)?).await?;
    let listener = tokio::net::TcpListener::bind(app.config.bind).await?;
    // Health is earned by this process's workers, never inherited from a previous run.
    sqlx::query("DELETE FROM worker_state")
        .execute(&app.db)
        .await?;
    sqlx::query("UPDATE chain_state SET healthy=0")
        .execute(&app.db)
        .await?;
    let workers = payroof::workers::start(app.clone());
    let result = axum::serve(
        listener,
        payroof::http::router(app.clone())
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown(app.clone()))
    .await;
    for worker in &workers {
        worker.abort();
    }
    for worker in workers {
        let _ = worker.await;
    }
    app.db.close().await;
    Ok(result?)
}
/// Readiness turns unavailable as soon as shutdown starts, so traffic drains first.
async fn shutdown(app: App) {
    terminated().await;
    app.draining.store(true, Ordering::Relaxed);
}
/// `healthcheck [URL]`: exits successfully when the readiness endpoint answers 200.
/// The container image runs it as its health probe, so it needs no shell or HTTP client.
fn healthcheck(url: &str) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("healthcheck needs an http:// URL"))?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let timeout = std::time::Duration::from_secs(3);
    let address = std::net::ToSocketAddrs::to_socket_addrs(host)?
        .next()
        .ok_or_else(|| anyhow::anyhow!("healthcheck host does not resolve"))?;
    let mut stream = std::net::TcpStream::connect_timeout(&address, timeout)?;
    let timeout = Some(timeout);
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    write!(
        stream,
        "GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )?;
    let mut status = [0; 12];
    stream.read_exact(&mut status)?;
    anyhow::ensure!(&status[9..] == b"200", "not ready");
    Ok(())
}
/// Resolves on Ctrl-C or SIGTERM.
async fn terminated() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {_ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {}}
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}
