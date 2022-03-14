use std::error::Error;
use std::path::Path;

use log::{debug, info};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use tokio::fs::{create_dir_all, read_to_string, write};

use crate::cert_store::store::CertificateStore;
use crate::cert_store::utils::{create_new_ca, create_new_key};

const LOCAL_FILES_PATH: &str = "./ca";
const LOCAL_KEY_PATH: &str = "./ca/ca.key";
const LOCAL_CERT_PATH: &str = "./ca/ca.crt";
const LOCAL_SERIAL_NUMBERS_PATH: &str = "./ca/serialnumbers";

#[derive(Debug, Default)]
pub struct LocalStore {
    cert: Option<X509>,
    key: Option<PKey<Private>>,
}

impl LocalStore {
    async fn load_key(&self) -> Result<PKey<Private>, Box<dyn Error>> {
        debug!("Load CA private key from local file path.");
        let path = Path::new(LOCAL_KEY_PATH);
        let content = read_to_string(path).await?;
        let key = PKey::private_key_from_pem(content.as_bytes())?;
        Ok(key)
    }

    async fn load_cert(&self) -> Result<X509, Box<dyn Error>> {
        debug!("Load CA certificate from local file path.");
        let path = Path::new(LOCAL_CERT_PATH);
        let content = read_to_string(path).await?;
        let cert = X509::from_pem(content.as_bytes())?;
        Ok(cert)
    }
}

#[tonic::async_trait]
impl CertificateStore for LocalStore {
    async fn init(&mut self) -> Result<(), Box<dyn Error>> {
        create_dir_all(LOCAL_FILES_PATH).await?;

        let key = match Path::new(LOCAL_KEY_PATH).exists() {
            true => self.load_key().await?,
            false => {
                info!("Key does not exist, create new.");
                let new_key = create_new_key()?;
                let key_path = Path::new(LOCAL_KEY_PATH);
                write(key_path, new_key.private_key_to_pem_pkcs8()?).await?;
                new_key
            }
        };

        let cert = match Path::new(LOCAL_CERT_PATH).exists() {
            true => self.load_cert().await?,
            false => {
                info!("CA certificate does not exist, create new.");
                let srn = self.next_serial_number().await?;
                let certificate = create_new_ca(srn, key.as_ref())?;
                let cert_path = Path::new(LOCAL_CERT_PATH);
                write(cert_path, certificate.to_pem()?).await?;
                certificate
            }
        };

        self.cert = Some(cert);
        self.key = Some(key);

        debug!("Initialized the local storage.");
        Ok(())
    }

    async fn next_serial_number(&self) -> Result<u32, Box<dyn Error>> {
        let path = Path::new(LOCAL_SERIAL_NUMBERS_PATH);

        let number = match path.exists() {
            true => {
                let content = read_to_string(path).await?;
                content.trim().parse()?
            }
            false => 0,
        };
        let next_number = number + 1;
        write(path, next_number.to_string()).await?;

        debug!("Fetched next serial number '{}'.", next_number);
        Ok(next_number)
    }

    fn cert(&self) -> &X509 {
        self.cert.as_ref().unwrap()
    }

    fn key(&self) -> &PKey<Private> {
        self.key.as_ref().unwrap()
    }
}

// TODO: Tests.
