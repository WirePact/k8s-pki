package main

import (
	"flag"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"wirepact.ch/k8s-pki/api"
	"wirepact.ch/k8s-pki/certificates"
)

var (
	port       = flag.Int("port", 8080, "Port for the pki server.")
	secretName = flag.String("secret", "wirepact-pki-ca", "Name of the Kubernetes secret for the ca certificate.")
)

func main() {
	flag.Parse()

	logrus.Debugln("Prepare CA.")
	certificates.PrepareCA(*secretName)

	logrus.Infof("Starting pki server on port ':%v'", *port)

	router := gin.Default()

	router.GET("ca", api.GetCA)
	router.POST("csr", api.HandleCSR)

	err := router.Run(fmt.Sprintf(":%v", *port))
	if err != nil {
		logrus.WithError(err).Fatal("Could not start server.")
	}
}
