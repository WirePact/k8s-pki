package kubernetes

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultNamespace         = "default"
	defaultDownwardApiEnv    = "POD_NAMESPACE"
	downwardApiNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	client             *kubernetes.Clientset
	loadedClientConfig clientcmd.ClientConfig
	currentNamespace   string
)

func GetCurrentNamespace() string {
	if currentNamespace != "" {
		return currentNamespace
	}

	result := defaultNamespace

	if loadedClientConfig != nil {
		result, _, _ = loadedClientConfig.Namespace()
	}

	if value, ok := os.LookupEnv(defaultDownwardApiEnv); ok {
		result = value
	}

	if _, err := os.Stat(downwardApiNamespaceFile); err == nil {
		data, _ := os.ReadFile(downwardApiNamespaceFile)
		result = strings.TrimSpace(string(data))
	}

	currentNamespace = result

	return result
}

func GetKubernetesClient() *kubernetes.Clientset {
	if client != nil {
		return client
	}

	var err error

	inCluster, _ := rest.InClusterConfig()
	if inCluster != nil {
		logrus.Debug("Returning Kubernetes client with in cluster config.")

		client, err = kubernetes.NewForConfig(inCluster)
		if err != nil {
			logrus.WithError(err).Fatalf("The Kubernetes client could not be instantiated from inCluster config.")
		}

		return client
	}

	fileConfig, _ := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	loadedClientConfig = clientcmd.NewDefaultClientConfig(*fileConfig, nil)
	clientConfig, err := loadedClientConfig.ClientConfig()
	if err != nil {
		logrus.WithError(err).Fatalf("Could not load client config.")
	}

	client, err = kubernetes.NewForConfig(clientConfig)
	if err != nil {
		logrus.WithError(err).Fatalf("Could not create client from client config.")
	}

	return client
}
