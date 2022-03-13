use std::error::Error;

use openssl::x509::{X509Req, X509};

#[tonic::async_trait]
pub trait CertificateStore: Send + Sync {
    async fn init(&mut self) -> Result<(), Box<dyn Error>>;
    async fn next_serial_number(&self) -> Result<u32, Box<dyn Error>>;
    async fn sign_csr(&self, request: X509Req) -> Result<X509, Box<dyn Error>>;
    fn cert(&self) -> &X509;
}
