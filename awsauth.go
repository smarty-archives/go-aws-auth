// Package awsauth implements AWS request signing using Signed Signature Version 2,
// Signed Signature Version 4, and the S3 Custom HTTP Authentication Scheme.
package awsauth

import (
	"net/http"
	"net/url"
	"time"
)

// Keys stores the authentication credentials to be used when signing requests.
// You can set them manually or leave it to awsauth to use environment variables.
var Keys *Credentials

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SecurityToken   string `json:"Token"`
	Expiration      string
}

// expired checks to see if the temporary credentials from an IAM role are
// within 4 minutes of expiration (The IAM documentation says that new keys
// will be provisioned 5 minutes before the old keys expire). Credentials
// that do not have an Expiration cannot expire.
func (k *Credentials) expired() bool {
	if k.Expiration == "" {
		// Credentials with no expiration can't expire
		return false
	}
	const awsform = "2006-01-02T15:04:05Z"
	t, _ := time.Parse(awsform, k.Expiration)
	expireTime := t.Add(4 * time.Minute)
	// if t + 4 mins is after now, true
	if expireTime.After(time.Now()) {
		return true
	} else {
		return false
	}
}

// Sign signs a request bound for AWS. It automatically chooses the best
// authentication scheme based on the service the request is going to.
func Sign(req *http.Request) *http.Request {
	service, _ := serviceAndRegion(req.URL.Host)
	sigVersion := awsSignVersion[service]

	switch sigVersion {
	case 2:
		return Sign2(req)
	case 3:
		return Sign3(req)
	case 4:
		return Sign4(req)
	case -1:
		return SignS3(req)
	}

	return nil
}

// Sign4 signs a request with Signed Signature Version 4.
func Sign4(req *http.Request) *http.Request {
	checkKeys()

	// Add the X-Amz-Security-Token header when using STS
	if Keys.SecurityToken != "" {
		req.Header.Set("X-Amz-Security-Token", Keys.SecurityToken)
	}

	prepareRequestV4(req)
	meta := new(metadata)

	// Task 1
	hashedCanonReq := hashedCanonicalRequestV4(req, meta)

	// Task 2
	stringToSign := stringToSignV4(req, hashedCanonReq, meta)

	// Task 3
	signingKey := signingKeyV4(Keys.SecretAccessKey, meta.date, meta.region, meta.service)
	signature := signatureV4(signingKey, stringToSign)

	req.Header.Set("Authorization", buildAuthHeaderV4(signature, meta))

	return req
}

// Sign3 signs a request with Signed Signature Version 3.
// If the service you're accessing supports Version 4, use that instead.
func Sign3(req *http.Request) *http.Request {
	checkKeys()

	// Add the X-Amz-Security-Token header when using STS
	if Keys.SecurityToken != "" {
		req.Header.Set("X-Amz-Security-Token", Keys.SecurityToken)
	}

	prepareRequestV3(req)

	// Task 1
	stringToSign := stringToSignV3(req)

	// Task 2
	signature := signatureV3(stringToSign)

	// Task 3
	req.Header.Set("X-Amzn-Authorization", buildAuthHeaderV3(signature))

	return req
}

// Sign2 signs a request with Signed Signature Version 2.
// If the service you're accessing supports Version 4, use that instead.
func Sign2(req *http.Request) *http.Request {
	checkKeys()

	// Add the SecurityToken parameter when using STS
	// This must be added before the signature is calculated
	if Keys.SecurityToken != "" {
		v := url.Values{}
		v.Set("SecurityToken", Keys.SecurityToken)
		augmentRequestQuery(req, v)

	}

	prepareRequestV2(req)

	stringToSign := stringToSignV2(req)
	signature := signatureV2(stringToSign)

	values := url.Values{}
	values.Set("Signature", signature)

	augmentRequestQuery(req, values)

	return req
}

// SignS3 signs a request bound for Amazon S3 using their custom
// HTTP authentication scheme.
func SignS3(req *http.Request) *http.Request {
	checkKeys()

	// Add the X-Amz-Security-Token header when using STS
	if Keys.SecurityToken != "" {
		req.Header.Set("X-Amz-Security-Token", Keys.SecurityToken)
	}

	prepareRequestS3(req)

	stringToSign := stringToSignS3(req)
	signature := signatureS3(stringToSign)

	authHeader := "AWS " + Keys.AccessKeyID + ":" + signature
	req.Header.Set("Authorization", authHeader)

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
	envSecurityToken   = "AWS_SECURITY_TOKEN"
)

var awsSignVersion = map[string]int{
	"autoscaling":          4,
	"cloudfront":           4,
	"cloudformation":       4,
	"cloudsearch":          4,
	"monitoring":           4,
	"dynamodb":             4,
	"ec2":                  2,
	"elasticmapreduce":     4,
	"elastictranscoder":    4,
	"elasticache":          2,
	"glacier":              4,
	"kinesis":              4,
	"redshift":             4,
	"rds":                  4,
	"sdb":                  2,
	"sns":                  4,
	"sqs":                  4,
	"s3":                   -1, // custom
	"elasticbeanstalk":     4,
	"importexport":         2,
	"iam":                  4,
	"route53":              3,
	"elasticloadbalancing": 4,
	"email":                3, // Simple Email Service (SES)
}
