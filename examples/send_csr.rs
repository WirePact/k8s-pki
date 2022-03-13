use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509Req};
use std::error::Error;
use tokio::fs::write;
use tonic::Request;

mod grpc {
    tonic::include_proto!("wirepact.pki");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client =
        grpc::pki_service_client::PkiServiceClient::connect("http://localhost:8080").await?;

    let my_key = create_new_key()?;
    write("./send_csr_key.key", my_key.private_key_to_pem_pkcs8()?).await?;

    let mut req_builder = X509Req::builder()?;
    req_builder.set_pubkey(my_key.as_ref())?;
    req_builder.set_version(2)?;
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "demo-csr")?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "WirePact PKI")?;
    let name = name.build();
    req_builder.set_subject_name(name.as_ref())?;
    req_builder.sign(my_key.as_ref(), MessageDigest::sha256())?;

    let req = req_builder.build();

    write("./send_csr_csr.csr", req.to_pem()?).await?;

    let response = client
        .sign_csr(Request::new(grpc::SignCsrRequest { csr: req.to_pem()? }))
        .await?;

    write("./send_csr_csr.crt", response.into_inner().certificate).await?;

    Ok(())
}

fn create_new_key() -> Result<PKey<Private>, Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    Ok(key)
}
