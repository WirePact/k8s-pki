package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"wirepact.ch/k8s-pki/certificates"
)

func GetCA(context *gin.Context) {
	logger := logrus.
		WithContext(context).
		WithFields(logrus.Fields{
			"host":   context.Request.Host,
			"path":   "/ca",
			"method": "GET",
		})

	logger.Infoln("Return CA to client.")

	context.Header("Content-Disposition", `attachment; filename="ca-cert.crt"`)
	context.Data(http.StatusOK, "application/x-x509-ca-cert", certificates.GetCA())
	context.Next()
}
