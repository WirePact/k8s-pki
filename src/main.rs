use clap::Parser;
use log::info;
use tonic::transport::Server;

use crate::cert_store::create_store;
use crate::pki_service::{grpc, PkiService};

mod cert_store;
mod pki_service;

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// The port that the server will listen on.
    #[clap(short, long, env, default_value = "8080")]
    port: u16,

    /// The Kubernetes secret that will store the PKI data.
    #[clap(short, long, env, default_value = "wirepact-pki-ca")]
    secret_name: String,

    /// If set, a local pki storage is used (local file system) instead
    /// of the Kubernetes secret.
    #[clap(short, long, env)]
    local: bool,

    /// If set, debug log messages are printed as well.
    #[clap(short, long, env)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    env_logger::builder()
        .filter_module(
            "k8s_pki",
            match cli.debug {
                true => log::LevelFilter::Debug,
                false => log::LevelFilter::Info,
            },
        )
        .init();

    let address = format!("0.0.0.0:{}", cli.port);

    info!("Creating and starting server @ {}", address);

    if cli.local {
        info!("Local mode enabled, storing CA and key in the local filesystem");
    } else {
        info!(
            "Local mode disabled, storing CA and key in the Kubernetes secret '{}'",
            cli.secret_name
        );
    }

    let mut store = create_store(cli.local, cli.secret_name);
    store.init().await?;
    let pki_service = PkiService { cert_store: store };

    #[cfg(windows)]
    async fn signal() {
        use tokio::signal::windows::ctrl_c;
        let mut stream = ctrl_c().unwrap();
        stream.recv().await;
        info!("Signal received. Shutting down server.");
    }

    #[cfg(unix)]
    async fn signal() {
        use log::debug;
        use tokio::signal::unix::{signal, SignalKind};

        let mut int = signal(SignalKind::interrupt()).unwrap();
        let mut term = signal(SignalKind::terminate()).unwrap();

        tokio::select! {
            _ = int.recv() => debug!("SIGINT received."),
            _ = term.recv() => debug!("SIGTERM received."),
        }

        info!("Signal received. Shutting down server.");
    }

    Server::builder()
        .add_service(grpc::pki_service_server::PkiServiceServer::new(pki_service))
        .serve_with_shutdown(address.parse()?, signal())
        .await?;

    Ok(())
}
