package awsauth

import (
	"net/http"
)

var Keys *Credentials

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

func Sign4(req *http.Request) *http.Request {
	checkKeys()
	prepareRequest(req)
	meta := new(metadata)

	// Task 1
	hashedCanonReq := hashedCanonicalRequest(req, meta)

	// Task 2
	stringToSign := stringToSign(req, hashedCanonReq, meta)

	// Task 3
	signingKey := signingKey(Keys.SecretAccessKey, meta.date, meta.region, meta.service)
	signature := signatureVersion4(signingKey, stringToSign)

	req.Header.Set("Authorization", buildAuthHeader(signature, meta))

	return req
}

type metadata struct {
	algorithm       string
	credentialScope string
	signedHeaders   string
	date            string
	region          string
	service         string
}

const (
	envAccessKeyID     = "AWS_ACCESS_KEY_ID"
	envSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
)
