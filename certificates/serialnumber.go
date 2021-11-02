package certificates

import (
	"strconv"

	v1 "k8s.io/api/core/v1"
)

// Load the next serialnumber from kubernetes.
// This information gets stored into the secret.
func getNextSerialnumber() int64 {
	var actualNumber int64

	updateSecretWithFunction(func(secret *v1.Secret) {
		actualNumber, _ = strconv.ParseInt(string(secret.Data[secretSerialnumberKey]), 10, 64)
		secret.Data[secretSerialnumberKey] = []byte(strconv.FormatInt(actualNumber+1, 10))
	})

	return actualNumber + 1
}
