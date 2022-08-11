use std::error::Error;

use log::info;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Req, X509};

#[tonic::async_trait]
pub trait CertificateStore: Send + Sync {
    async fn init(&mut self) -> Result<(), Box<dyn Error>>;
    fn cert(&self) -> &X509;
    fn key(&self) -> &PKey<Private>;

    async fn sign_csr(&self, request: X509Req) -> Result<X509, Box<dyn Error>> {
        let ca_cert = self.cert();
        let ca_key = self.key();
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365 * 5)?;

        let mut builder = X509::builder()?;
        builder.set_version(request.version())?;
        builder.set_subject_name(request.subject_name())?;
        builder.set_pubkey(request.public_key()?.as_ref())?;
        builder.set_not_before(not_before.as_ref())?;
        builder.set_not_after(not_after.as_ref())?;

        builder.append_extension(BasicConstraints::new().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        builder.append_extension(
            ExtendedKeyUsage::new()
                .client_auth()
                .server_auth()
                .build()?,
        )?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(ca_cert), None))?;
        builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&builder.x509v3_context(Some(ca_cert), None))?;
        builder.append_extension(auth_key_identifier)?;

        builder.set_issuer_name(ca_cert.subject_name())?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        builder.set_serial_number(&serial_number)?;
        builder.sign(ca_key.as_ref(), MessageDigest::sha256())?;

        info!("Sign CSR for '{:?}'.", request.subject_name());

        Ok(builder.build())
    }
}
