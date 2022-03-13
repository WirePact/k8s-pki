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
    #[clap(short, long)]
    local: bool,

    /// If set, debug log messages are printed as well.
    #[clap(short, long, env)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    env_logger::builder()
        .filter_level(match cli.debug {
            true => log::LevelFilter::Debug,
            false => log::LevelFilter::Info,
        })
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

    let mut store = create_store(cli.local);
    store.init().await?;
    let pki_service = PkiService { cert_store: store };

    Server::builder()
        .add_service(grpc::pki_service_server::PkiServiceServer::new(pki_service))
        .serve(address.parse()?)
        .await?;

    Ok(())
}
