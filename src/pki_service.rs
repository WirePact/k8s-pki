use log::{debug, warn};
use openssl::x509::X509Req;
use tonic::{Code, Request, Response, Status};

use crate::cert_store::store::CertificateStore;
use crate::pki_service::grpc::{CaCertificate, SignCsrRequest, SignCsrResponse};

pub struct PkiService {
    cert_store: Box<dyn CertificateStore>,
    api_key: Option<String>,
}

impl PkiService {
    pub fn new(cert_store: Box<dyn CertificateStore>, api_key: Option<String>) -> Self {
        Self {
            cert_store,
            api_key,
        }
    }

    fn check_api_key<T>(&self, request: &Request<T>) -> bool {
        match self.api_key.as_ref() {
            None => {
                debug!("No API key configured, allowing all requests.");
                true
            }
            Some(key) => {
                let auth_header = request.metadata().get("Authorization");
                match auth_header {
                    Some(header) => {
                        let header_key = header.to_str().unwrap();
                        let result = header_key == key;
                        if !result {
                            warn!("Authorization key ({}) in request does not match configured key ({})", key, header_key);
                        }
                        result
                    }
                    None => {
                        warn!("No Authorization header found in request, but an API key was provided.");
                        false
                    }
                }
            }
        }
    }
}

pub mod grpc {
    tonic::include_proto!("wirepact.pki");
}

#[tonic::async_trait]
impl grpc::pki_service_server::PkiService for PkiService {
    async fn get_ca(&self, request: Request<()>) -> Result<Response<CaCertificate>, Status> {
        if !self.check_api_key(&request) {
            return Err(Status::new(Code::PermissionDenied, "Invalid API key"));
        }

        debug!("Returning ca certificate to caller.");
        let pem = match self.cert_store.cert().to_pem() {
            Ok(pem) => Ok(pem),
            Err(_) => Err(Status::new(
                Code::Internal,
                "Could not load or serialize ca certificate.",
            )),
        }?;

        Ok(Response::new(CaCertificate { certificate: pem }))
    }

    async fn sign_csr(
        &self,
        request: Request<SignCsrRequest>,
    ) -> Result<Response<SignCsrResponse>, Status> {
        if !self.check_api_key(&request) {
            return Err(Status::new(Code::PermissionDenied, "Invalid API key"));
        }

        let csr = match X509Req::from_pem(request.into_inner().csr.as_slice()) {
            Ok(req) => Ok(req),
            Err(e) => {
                debug!("{:#?}", e);
                Err(Status::new(
                    Code::InvalidArgument,
                    "The CSR could not be parsed from pem format.",
                ))
            }
        }?;

        let cert = match self.cert_store.sign_csr(csr).await {
            Ok(c) => Ok(c),
            Err(_) => Err(Status::new(Code::Internal, "Could not sign the CSR.")),
        }?;

        let pem = match cert.to_pem() {
            Ok(pem) => Ok(pem),
            Err(_) => Err(Status::new(
                Code::Internal,
                "Could not load or serialize certificate.",
            )),
        }?;

        debug!("Return signed certificate to requester.");
        Ok(Response::new(SignCsrResponse { certificate: pem }))
    }
}
