use log::debug;
use openssl::x509::X509Req;
use tonic::{Code, Request, Response, Status};

use crate::cert_store::store::CertificateStore;
use crate::pki_service::grpc::{CaCertificate, SignCsrRequest, SignCsrResponse};

pub struct PkiService {
    pub(crate) cert_store: Box<dyn CertificateStore>,
}

pub mod grpc {
    tonic::include_proto!("wirepact.pki");
}

#[tonic::async_trait]
impl grpc::pki_service_server::PkiService for PkiService {
    async fn get_ca(&self, _: Request<()>) -> Result<Response<CaCertificate>, Status> {
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
