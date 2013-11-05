package awsauth

import (
	"net/http"
	"net/url"
)

var Keys *Credentials

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

func Sign4(req *http.Request) *http.Request {
	checkKeys()
	prepareRequestV4(req)
	meta := new(metadata)

	// Task 1
	hashedCanonReq := hashedCanonicalRequestV4(req, meta)

	// Task 2
	stringToSign := stringToSignV4(req, hashedCanonReq, meta)

	// Task 3
	signingKey := signingKeyV4(Keys.SecretAccessKey, meta.date, meta.region, meta.service)
	signature := signatureV4(signingKey, stringToSign)

	req.Header.Set("Authorization", buildAuthHeader(signature, meta))

	return req
}

func Sign2(req *http.Request) *http.Request {
	checkKeys()
	prepareRequestV2(req)

	stringToSign := stringToSignV2(req)
	signature := signatureV2(stringToSign)

	values := url.Values{}
	values.Set("Signature", signature)

	augmentRequestQuery(req, values)

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

var awsSignVersion = map[string]int{
	"autoscaling":       4,
	"cloudformation":    4,
	"cloudsearch":       4,
	"monitoring":        4,
	"dynamodb":          4,
	"ec2":               2,
	"elasticmapreduce":  4,
	"elastictranscoder": 4,
	"elasticache":       2,
	//"authorize":            ???,
	//"fps":                  ???,
	"glacier": 4,
	//"mechanicalturk":       ???,
	"redshift": 4,
	"rds":      4,
	//"email":                ???,
	"sdb": 2,
	"sns": 4,
	"sqs": 4,
	"s3":  0, // custom... thanks, Amazon...
	//"swf":                  ???,
	//"directconnect":        ???,
	"elasticbeanstalk": 4,
	//"storagegateway":       ???,
	"importexport": 2,
	"iam":          4,
	//"opsworks":             ???,
	"elasticloadbalancing": 4,
}
