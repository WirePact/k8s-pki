package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

var ca *x509.Certificate
var caCertificates *tls.Certificate

// PrepareCA loads the secret in the actual namespace that
// contains the CA certificate for the PKI. If no certificate
// is found, the PKI creates a new CA certificate and stores it
// in the defined Kubernetes secret.
func PrepareCA(secretName string) {
	initSecret(secretName)

	if doesSecretExist() {
		// secret is found. Load CA from secret.
		caCertificates, ca = loadCA()
	} else {
		// Secret is not found. Create CA and secret.
		createSecret()
		caCertificates, ca = createCA()
	}
}

func GetCA() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
}

func SignCSR(csrBytes []byte) ([]byte, error) {
	csrBlock, _ := pem.Decode(csrBytes)
	clientCSR, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}

	err = clientCSR.CheckSignature()
	if err != nil {
		return nil, err
	}

	clientCertificate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(getNextSerialnumber()),
		Issuer:       ca.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	clientCertRaw, err := x509.CreateCertificate(rand.Reader, &clientCertificate, ca, clientCSR.PublicKey, caCertificates.PrivateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertRaw}), nil
}

func createCA() (*tls.Certificate, *x509.Certificate) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(getNextSerialnumber()),
		Subject: pkix.Name{
			Organization: []string{"WirePact PKI CA"},
			Country:      []string{"Kubernetes"},
			CommonName:   "PKI",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	caCert, err := x509.CreateCertificate(rand.Reader, ca, ca, publicKey, privateKey)
	if err != nil {
		logrus.WithError(err).Fatalln("Could not create CA certificate")
	}
	logrus.Debugln("Created CA certificate")

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert})
	logrus.Debugln("Wrote CA certificate bytes")

	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	logrus.Debugln("Wrote Private Key bytes")

	updateSecretWithFunction(func(secret *v1.Secret) {
		secret.Data[secretCACertKey] = certOut
		secret.Data[secretCAKeyKey] = keyOut
	})

	logrus.Infoln("Created and stored CA certificate with private key.")

	caCertificates, err := tls.X509KeyPair(certOut, keyOut)
	if err != nil {
		logrus.WithError(err).Fatalln("Could not correctly load CA certificate.")
	}

	ca, err = x509.ParseCertificate(caCertificates.Certificate[0])
	if err != nil {
		logrus.WithError(err).Fatalln("Could not correctly parse CA certificate.")
	}

	return &caCertificates, ca
}

func loadCA() (*tls.Certificate, *x509.Certificate) {
	secret := getSecret()

	caCertificates, err := tls.X509KeyPair(secret.Data[secretCACertKey], secret.Data[secretCAKeyKey])
	if err != nil {
		logrus.WithError(err).Fatalln("Could not correctly load CA certificate.")
	}

	ca, err := x509.ParseCertificate(caCertificates.Certificate[0])
	if err != nil {
		logrus.WithError(err).Fatalln("Could not correctly parse CA certificate.")
	}

	return &caCertificates, ca
}
