use std::error::Error;

use log::info;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Req, X509};

#[tonic::async_trait]
pub trait CertificateStore: Send + Sync {
    async fn init(&mut self) -> Result<(), Box<dyn Error>>;
    async fn next_serial_number(&self) -> Result<u32, Box<dyn Error>>;
    fn cert(&self) -> &X509;
    fn key(&self) -> &PKey<Private>;

    async fn sign_csr(&self, request: X509Req) -> Result<X509, Box<dyn Error>> {
        let ca_cert = self.cert();
        let ca_key = self.key();
        let next_number = self.next_serial_number().await?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365 * 5)?;

        let mut builder = X509::builder()?;
        builder.set_version(request.version())?;
        builder.set_subject_name(request.subject_name())?;
        builder.set_pubkey(request.public_key()?.as_ref())?;
        builder.set_not_before(not_before.as_ref())?;
        builder.set_not_after(not_after.as_ref())?;

        match request.extensions() {
            Ok(extensions) => extensions
                .iter()
                .map(|ext| builder.append_extension2(ext))
                .collect::<Result<Vec<_>, _>>()
                .map(|_| ()),
            _ => Ok(()),
        }?;
        builder.set_issuer_name(ca_cert.subject_name())?;
        builder.set_serial_number(
            Asn1Integer::from_bn(BigNum::from_u32(next_number)?.as_ref())?.as_ref(),
        )?;
        builder.sign(ca_key.as_ref(), MessageDigest::sha256())?;

        info!(
            "Sign CSR for '{:?}' with serial number '{}'.",
            request.subject_name(),
            next_number
        );

        Ok(builder.build())
    }
}
