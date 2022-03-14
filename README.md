# Kubernetes PKI for WirePact

This is the PKI for WirePact in Kubernetes.

The PKI is responsible to provide translators and other types of
participants with key material used in WirePact to sign
the transmitted identity and to create the mTLS connection.

Read about WirePact (aka Distributed Authentication Mesh) in
[Distributed Authentication Mesh](https://buehler.github.io/mse-project-thesis-1/report.pdf)
and [Common Identities in a Distributed Authentication Mesh](https://buehler.github.io/mse-project-thesis-2/report.pdf).

The operator will install a PKI it its own namespace in Kubernetes.
To communicate with the PKI, use the provided
[proto file](./proto/pki.proto)
to fetch the CA certificate as well as send a certificate signing
request to the PKI.

To see an example (in rust), head over to the
[example file](./examples/send_csr.rs).

### Configuration

The PKI can be configured via environment variables or command line
arguments.

- `PORT` (`-p --port <PORT>`): Defines the port that the PKI listens
  to gRPC connections (Default: `8080`)
- `SECRET_NAME` (`-s --secret-name <NAME>`): The name of the Kubernetes
  secret, that stores the CA and the key (Default: `wirepact-pki-ca`)
- `LOCAL` (`-l --local`): If set (debug variable), the CA and
  other elements of the material gets
  stored locally instead of a Kubernetes secret
- `DEBUG` (`-d --debug`): If set, debug log messages are emitted
  by the PKI
