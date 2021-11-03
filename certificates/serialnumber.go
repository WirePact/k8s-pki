package certificates

import (
	"os"
	"strconv"

	v1 "k8s.io/api/core/v1"
)

// Load the next serialnumber from kubernetes.
// This information gets stored into the secret.
func getNextSerialnumber() int64 {
	var actualNumber int64

	if caLocalMode {
		if _, err := os.Stat("ca_serialnumbers"); err != nil {
			actualNumber = 0
			serialFile, _ := os.Create("ca_serialnumbers")
			_, _ = serialFile.WriteString("1")
			_ = serialFile.Close()
		} else {
			bytes, _ := os.ReadFile("ca_serialnumbers")
			actualNumber, _ = strconv.ParseInt(string(bytes), 10, 64)
			serialFile, _ := os.Create("ca_serialnumbers")
			_, _ = serialFile.WriteString(strconv.FormatInt(actualNumber+1, 10))
			_ = serialFile.Close()
		}
	} else {
		updateSecretWithFunction(func(secret *v1.Secret) {
			actualNumber, _ = strconv.ParseInt(string(secret.Data[secretSerialnumberKey]), 10, 64)
			secret.Data[secretSerialnumberKey] = []byte(strconv.FormatInt(actualNumber+1, 10))
		})
	}

	return actualNumber + 1
}
