use std::error::Error;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509Name, X509};

pub fn create_new_key() -> Result<PKey<Private>, Box<dyn Error>> {
    let rsa = Rsa::generate(2048)?;
    let key = PKey::from_rsa(rsa)?;

    Ok(key)
}

pub fn create_new_ca(key: &PKeyRef<Private>) -> Result<X509, Box<dyn Error>> {
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "PKI")?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "WirePact PKI CA")?;
    let name = name.build();

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365 * 5)?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    builder.set_serial_number(&serial_number)?;

    builder.set_not_before(not_before.as_ref())?;
    builder.set_not_after(not_after.as_ref())?;
    builder.set_pubkey(key)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_key_identifier)?;

    builder.sign(key, MessageDigest::sha256())?;

    Ok(builder.build())
}
