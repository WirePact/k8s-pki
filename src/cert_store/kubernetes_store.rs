use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::path::Path;

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::PostParams;
use kube::config::Kubeconfig;
use kube::{Api, Client};
use log::{debug, info};
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::{X509Ref, X509};
use tokio::fs::read_to_string;

use crate::cert_store::store::CertificateStore;
use crate::cert_store::utils::{create_new_ca, create_new_key};

const SECRET_KEY: &str = "caKey";
const SECRET_CERTIFICATE: &str = "caCert";
const SECRET_SERIAL_NUMBER: &str = "serialNumber";

const DEFAULT_NAMESPACE: &str = "default";
const DOWNWARD_API_ENV: &str = "POD_NAMESPACE";
const DOWNWARD_API_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

#[derive(Debug, Default)]
pub struct KubernetesStore {
    pub(super) secret_name: String,
    cert: Option<X509>,
    key: Option<PKey<Private>>,
}

impl KubernetesStore {
    async fn current_namespace(&self) -> Result<String, Box<dyn Error>> {
        if let Ok(config) = Kubeconfig::read() {
            let default_context = "".to_string();
            let current_context_name = config.current_context.as_ref().unwrap_or(&default_context);
            let current_namespace = config
                .contexts
                .iter()
                .find(|&ctx| ctx.name == *current_context_name)
                .expect("No context with name found.")
                .clone()
                .context
                .namespace
                .unwrap_or_else(|| "".to_string());

            if !current_namespace.is_empty() {
                return Ok(current_namespace);
            }
        }

        if let Ok(value) = env::var(DOWNWARD_API_ENV) {
            return Ok(value);
        }

        let path = Path::new(DOWNWARD_API_FILE);
        if path.exists() {
            let content = read_to_string(path).await?;
            return Ok(content.trim().to_string());
        }

        Ok(DEFAULT_NAMESPACE.to_string())
    }

    async fn load_secret(&self) -> Result<Secret, Box<dyn Error>> {
        debug!("Load Kubernetes secret.");

        let client = Client::try_default().await?;
        let secrets: Api<Secret> =
            Api::namespaced(client, self.current_namespace().await?.as_str());

        let secret = secrets.get(self.secret_name.as_str()).await;
        match secret {
            Ok(secret) => Ok(secret),
            Err(_) => {
                info!(
                    "Kubernetes secret '{}' does not exist, create it.",
                    self.secret_name
                );
                let mut secret = Secret::default();
                secret.metadata.name = Some(self.secret_name.clone());

                let mut annotations = BTreeMap::new();
                annotations.insert("controlled-by".to_string(), "wirepact-k8s-pki".to_string());
                secret.metadata.annotations = Some(annotations);

                let mut data = BTreeMap::new();
                data.insert(SECRET_SERIAL_NUMBER.to_string(), "0".to_string());
                data.insert(SECRET_KEY.to_string(), "".to_string());
                data.insert(SECRET_CERTIFICATE.to_string(), "".to_string());
                secret.string_data = Some(data);

                let secret = secrets.create(&PostParams::default(), &secret).await?;
                Ok(secret)
            }
        }
    }

    async fn store_secret(&self, secret: &Secret) -> Result<(), Box<dyn Error>> {
        debug!("Store Kubernetes secret.");

        let client = Client::try_default().await?;
        let secrets: Api<Secret> =
            Api::namespaced(client, self.current_namespace().await?.as_str());

        secrets
            .replace(self.secret_name.as_str(), &PostParams::default(), secret)
            .await?;
        Ok(())
    }

    async fn load_key(&self) -> Result<Option<PKey<Private>>, Box<dyn Error>> {
        debug!("Load CA private key from Kubernetes secret.");

        let secret = self.load_secret().await?;
        Ok(match secret.data.unwrap().get(SECRET_KEY) {
            None => None,
            Some(data) => match PKey::private_key_from_pem(data.0.as_slice()) {
                Ok(key) => Some(key),
                Err(_) => None,
            },
        })
    }

    async fn store_key(&self, key: &PKeyRef<Private>) -> Result<(), Box<dyn Error>> {
        debug!("Store CA private key to Kubernetes secret.");

        let mut secret = self.load_secret().await?;
        if let Some(mut data) = secret.data {
            *data.entry(SECRET_KEY.to_string()).or_default() =
                ByteString(key.private_key_to_pem_pkcs8()?);
            secret.data = Some(data);
        }

        self.store_secret(&secret).await?;
        Ok(())
    }

    async fn load_cert(&self) -> Result<Option<X509>, Box<dyn Error>> {
        debug!("Load CA certificate from Kubernetes secret.");

        let secret = self.load_secret().await?;
        Ok(match secret.data.unwrap().get(SECRET_CERTIFICATE) {
            None => None,
            Some(data) => match X509::from_pem(data.0.as_slice()) {
                Ok(cert) => Some(cert),
                Err(_) => None,
            },
        })
    }

    async fn store_cert(&self, cert: &X509Ref) -> Result<(), Box<dyn Error>> {
        debug!("Store CA certificate to Kubernetes secret.");

        let mut secret = self.load_secret().await?;
        if let Some(mut data) = secret.data {
            *data.entry(SECRET_CERTIFICATE.to_string()).or_default() = ByteString(cert.to_pem()?);
            secret.data = Some(data);
        }

        self.store_secret(&secret).await?;
        Ok(())
    }

    async fn load_serial_number(&self) -> Result<u32, Box<dyn Error>> {
        debug!("Load CA serial number from Kubernetes secret.");

        let secret = self.load_secret().await?;
        Ok(match secret.data.unwrap().get(SECRET_SERIAL_NUMBER) {
            None => 0,
            Some(data) => String::from_utf8(data.0.to_vec())?.parse()?,
        })
    }

    async fn store_serial_number(&self, number: u32) -> Result<(), Box<dyn Error>> {
        debug!("Store CA serial number to Kubernetes secret.");

        let mut secret = self.load_secret().await?;
        if let Some(mut data) = secret.data {
            *data.entry(SECRET_SERIAL_NUMBER.to_string()).or_default() =
                ByteString(number.to_string().into_bytes());
            secret.data = Some(data);
        }

        self.store_secret(&secret).await?;
        Ok(())
    }
}

#[tonic::async_trait]
impl CertificateStore for KubernetesStore {
    async fn init(&mut self) -> Result<(), Box<dyn Error>> {
        let key = self.load_key().await?;
        let key = match key {
            Some(key) => key,
            None => {
                info!("Key does not exist, create new.");
                let new_key = create_new_key()?;
                self.store_key(new_key.as_ref()).await?;
                new_key
            }
        };

        let cert = self.load_cert().await?;
        let cert = match cert {
            Some(cert) => cert,
            None => {
                info!("CA certificate does not exist, create new.");
                let srn = self.next_serial_number().await?;
                let certificate = create_new_ca(srn, key.as_ref())?;
                self.store_cert(certificate.as_ref()).await?;
                certificate
            }
        };

        self.cert = Some(cert);
        self.key = Some(key);

        debug!("Initialized the Kubernetes secret storage.");
        Ok(())
    }

    async fn next_serial_number(&self) -> Result<u32, Box<dyn Error>> {
        let number = self.load_serial_number().await?;
        let next_number = number + 1;
        self.store_serial_number(next_number).await?;

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
