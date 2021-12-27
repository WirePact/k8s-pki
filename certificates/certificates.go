package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

var ca *x509.Certificate
var caCertificates *tls.Certificate
var caLocalMode bool

// PrepareCA loads the secret in the actual namespace that
// contains the CA certificate for the PKI. If no certificate
// is found, the PKI creates a new CA certificate and stores it
// in the defined Kubernetes secret. If localMode is set,
// the ca gets created in the filesystem instead of the Kubernetes secret.
func PrepareCA(secretName string, localMode bool) {
	caLocalMode = localMode
	if !localMode {
		initSecret(secretName)
	}

	if caExists() {
		// secret is found. Load CA from secret/file.
		caCertificates, ca = loadCA()
	} else {
		// Secret is not found. Create CA and secret/file.
		if !localMode && !doesSecretExist() {
			createSecret()
		}
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

func caExists() bool {
	if caLocalMode {
		if _, err := os.Stat("ca.crt"); err == nil {
			return true
		} else {
			return false
		}
	} else if doesSecretExist() {
		secret := getSecret()
		_, certOk := secret.Data[secretCACertKey]
		_, keyOk := secret.Data[secretCAKeyKey]
		return certOk && keyOk
	}

	return false
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

	if caLocalMode {
		certFile, err := os.Create("ca.crt")
		if err != nil {
			logrus.WithError(err).Fatalln("Could not create CA certificate file 'ca.crt'.")
		}
		_, _ = certFile.Write(certOut)
		_ = certFile.Close()

		keyFile, err := os.Create("ca.key")
		if err != nil {
			logrus.WithError(err).Fatalln("Could not create CA key file 'ca.key'.")
		}
		_, _ = keyFile.Write(keyOut)
		_ = keyFile.Close()
	} else {
		updateSecretWithFunction(func(secret *v1.Secret) {
			secret.Data[secretCACertKey] = certOut
			secret.Data[secretCAKeyKey] = keyOut
		})
	}

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

	var caCertificates tls.Certificate
	var err error

	if caLocalMode {
		caCertificates, err = tls.LoadX509KeyPair("ca.crt", "ca.key")
		if err != nil {
			logrus.WithError(err).Fatalln("Could not correctly load CA certificate from files.")
		}
	} else {
		secret := getSecret()
		caCertificates, err = tls.X509KeyPair(secret.Data[secretCACertKey], secret.Data[secretCAKeyKey])
		if err != nil {
			logrus.WithError(err).Fatalln("Could not correctly load CA certificate from Kubernetes.")
		}
	}

	ca, err := x509.ParseCertificate(caCertificates.Certificate[0])
	if err != nil {
		logrus.WithError(err).Fatalln("Could not correctly parse CA certificate.")
	}

	return &caCertificates, ca
}
