package api

import (
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"wirepact.ch/k8s-pki/certificates"
)

func HandleCSR(context *gin.Context) {
	logger := logrus.
		WithContext(context).
		WithFields(logrus.Fields{
			"host":   context.Request.Host,
			"path":   "/csr",
			"method": "POST",
		})

	logger.Debugln("Handling CSR for client.")

	if context.Request.Body == nil {
		context.String(http.StatusBadRequest, "Body missing.")
		context.Abort()
		return
	}

	csrBytes, _ := ioutil.ReadAll(context.Request.Body)
	clientCertificate, err := certificates.SignCSR(csrBytes)
	if err != nil {
		logger.WithError(err).Warnln("Could not create client cert.")
		context.String(http.StatusBadRequest, "Could not create certificate from CSR.")
		context.Abort()
		return
	}

	logger.Infoln("Successfully signed CSR of client.")

	context.Header("Content-Disposition", `attachment; filename="client-cert.crt"`)
	context.Data(http.StatusOK, "application/x-x509-user-cert", clientCertificate)
	context.Next()
}
