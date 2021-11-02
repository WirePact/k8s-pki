package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"net/http"

	"github.com/sirupsen/logrus"
)

func main() {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	csr := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"WirePact PKI"},
			CommonName:   "demo-authenticator",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, privateKey)
	if err != nil {
		logrus.WithError(err).Fatalln("Could not create CSR.")
	}

	csrBuffer := &bytes.Buffer{}
	_ = pem.Encode(csrBuffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	response, err := http.Post("http://localhost:8080/csr", "application/pkcs10", csrBuffer)
	if err != nil {
		logrus.WithError(err).Fatalln("Could not post CSR.")
	}

	certBytes, _ := ioutil.ReadAll(response.Body)
	certBlock, _ := pem.Decode(certBytes)
	clientCertificate, _ := x509.ParseCertificate(certBlock.Bytes)

	logrus.Infof("The issuer '%v' successfully signed the CSR for '%v' with the serial number '%v'.",
		clientCertificate.Issuer.String(),
		clientCertificate.Subject.String(),
		clientCertificate.SerialNumber)
}
