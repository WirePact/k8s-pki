package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"wirepact.ch/k8s-pki/api"
	"wirepact.ch/k8s-pki/certificates"
)

var (
	port       = flag.Int("port", 8080, "Port for the pki server.")
	secretName = flag.String("secret", "wirepact-pki-ca", "Name of the Kubernetes secret for the ca certificate.")
	localMode  = flag.Bool("local", false, "If set, does not use Kubernetes for secret storage but a local file beside the app.")
)

func main() {
	flag.Parse()

	logrus.Debugln("Prepare CA.")
	if *localMode {
		logrus.Infof("-local is set, use local filesystem to store CA.")
	} else {
		logrus.Infof("-local is not set, use Kubernetes secret '%v' to store CA.", *secretName)
	}

	certificates.PrepareCA(*secretName, *localMode)

	logrus.Infof("Starting pki server on port ':%v'", *port)

	router := gin.Default()

	router.GET("ca", api.GetCA)
	router.POST("csr", api.HandleCSR)
	router.GET("healthz", func(context *gin.Context) {
		context.String(http.StatusOK, "healthy")
	})

	err := router.Run(fmt.Sprintf(":%v", *port))
	if err != nil {
		logrus.WithError(err).Fatal("Could not start server.")
	}
}
