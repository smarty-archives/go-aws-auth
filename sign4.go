package awsauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

func hashedCanonicalRequest(req *http.Request, meta *metadata) string {
	// TASK 1. http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

	payload := readAndReplaceBody(req)
	hashedPayload := hashSHA256(payload)

	contentType := req.Header.Get("Content-Type")
	reqTs := req.Header.Get("X-Amz-Date")
	headersToSign := concat("\n", "content-type:"+contentType, "host:"+req.Host, "x-amz-date:"+reqTs) + "\n"
	meta.signedHeaders = "content-type;host;x-amz-date"

	canonicalRequest := concat("\n", req.Method, req.URL.Path, req.URL.RawQuery, headersToSign, meta.signedHeaders, hashedPayload)
	return hashSHA256(canonicalRequest)
}

func stringToSignV4(req *http.Request, hashedCanonReq string, meta *metadata) string {
	// TASK 2. http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html

	requestTs := req.Header.Get("X-Amz-Date")

	meta.algorithm = "AWS4-HMAC-SHA256"
	meta.service, meta.region = serviceAndRegion(req.Host)
	meta.date = tsDate(requestTs)
	meta.credentialScope = concat("/", meta.date, meta.region, meta.service, "aws4_request")

	return concat("\n", meta.algorithm, requestTs, meta.credentialScope, hashedCanonReq)
}

func signatureVersion4(signingKey []byte, stringToSign string) string {
	// TASK 3. http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

	return hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
}

func prepareRequest(req *http.Request) *http.Request {
	necessaryDefaults := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
		"X-Amz-Date":   timestampV4(),
	}

	for header, value := range necessaryDefaults {
		if req.Header.Get(header) == "" {
			req.Header.Set(header, value)
		}
	}

	if req.URL.Path == "" {
		req.URL.Path += "/"
	}

	return req
}

func signingKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

func readAndReplaceBody(req *http.Request) string {
	rawPayload, _ := ioutil.ReadAll(req.Body)
	payload := string(rawPayload)
	req.Body = ioutil.NopCloser(strings.NewReader(payload))
	return payload
}

func serviceAndRegion(host string) (string, string) {
	var region, service string
	parts := strings.Split(host, ".")
	service = parts[0]
	if len(parts) >= 4 {
		region = parts[1]
	} else {
		region = "us-east-1" // default. http://docs.aws.amazon.com/general/latest/gr/rande.html
	}
	return service, region
}

func buildAuthHeader(signature string, meta *metadata) string {
	credential := Keys.AccessKeyID + "/" + meta.credentialScope

	return meta.algorithm +
		" Credential=" + credential +
		", SignedHeaders=" + meta.signedHeaders +
		", Signature=" + signature
}

func checkKeys() {
	if Keys == nil {
		Keys = &Credentials{
			os.Getenv(envAccessKeyID),
			os.Getenv(envSecretAccessKey),
		}
	}
}

func hashSHA256(content string) string {
	h := sha256.New()
	h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func timestampV4() string {
	t := now().Format(time.RFC3339)
	t = strings.Replace(t, ":", "", -1)
	t = strings.Replace(t, "-", "", -1)
	return t
}

func tsDate(timestamp string) string {
	return timestamp[:8]
}

func concat(delim string, str ...string) string {
	return strings.Join(str, delim)
}

func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

var now = func() time.Time {
	return time.Now().UTC()
}
