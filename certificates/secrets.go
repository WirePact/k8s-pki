package certificates

import (
	"context"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"wirepact.ch/k8s-pki/kubernetes"
)

const (
	secretSerialnumberKey = "serialNumber"
	secretCACertKey       = "caCertificate"
	secretCAKeyKey        = "caCertificateKey"
)

var kubernetesSecretName string

func initSecret(name string) {
	kubernetesSecretName = name
}

func getSecret() *v1.Secret {
	client := kubernetes.GetKubernetesClient()
	secret, err := client.CoreV1().Secrets(kubernetes.GetCurrentNamespace()).Get(context.TODO(), kubernetesSecretName, metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Fatalf("Error during retrieval of secret.")
	}

	return secret
}

func createSecret() {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: kubernetesSecretName,
			Annotations: map[string]string{
				"controlled-by": "wirepact-k8s-pki",
			},
		},
		Data: map[string][]byte{
			secretSerialnumberKey: []byte("0"),
		},
	}

	client := kubernetes.GetKubernetesClient()
	_, err := client.CoreV1().Secrets(kubernetes.GetCurrentNamespace()).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		logrus.WithError(err).Fatalln("Could not create Kubernetes secret.")
	}
}

func doesSecretExist() bool {
	client := kubernetes.GetKubernetesClient()
	_, err := client.CoreV1().Secrets(kubernetes.GetCurrentNamespace()).Get(context.TODO(), kubernetesSecretName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		logrus.WithError(err).Fatalf("Error during retrieval of secret.")
	}

	if err == nil {
		return true
	}

	return false
}

func updateSecret(key string, data []byte) {
	client := kubernetes.GetKubernetesClient()
	secret, err := client.CoreV1().Secrets(kubernetes.GetCurrentNamespace()).Get(context.TODO(), kubernetesSecretName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		logrus.WithError(err).Fatalf("Error during retrieval of secret.")
	}

	secret.Data[key] = data

	_, err = client.CoreV1().Secrets(kubernetes.GetCurrentNamespace()).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Fatalln("Could not write Kubernetes secret.")
	}
}

type secretUpdater func(*v1.Secret)

func updateSecretWithFunction(worker secretUpdater) {
	client := kubernetes.GetKubernetesClient()
	secret, err := client.CoreV1().Secrets(kubernetes.GetCurrentNamespace()).Get(context.TODO(), kubernetesSecretName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		logrus.WithError(err).Fatalf("Error during retrieval of secret.")
	}

	worker(secret)

	_, err = client.CoreV1().Secrets(kubernetes.GetCurrentNamespace()).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Fatalln("Could not write Kubernetes secret.")
	}
}
