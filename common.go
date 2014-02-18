package awsauth

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func serviceAndRegion(host string) (string, string) {
	var region, service string
	parts := strings.Split(host, ".")

	service = parts[0]

	if len(parts) >= 4 {
		if parts[1] == "s3" {
			region = parts[0]
			service = parts[1]
		} else {
			region = parts[1]
		}
	} else {
		if strings.HasPrefix(parts[0], "s3-") {
			service = parts[0][:2]
			region = parts[0][3:]
		} else {
			region = "us-east-1" // default. http://docs.aws.amazon.com/general/latest/gr/rande.html
		}
	}

	return service, region
}

func checkKeys() {
	if Keys == nil {
		Keys = &Credentials{
			AccessKeyID:     os.Getenv(envAccessKeyID),
			SecretAccessKey: os.Getenv(envSecretAccessKey),
			SecurityToken:   os.Getenv(envSecurityToken),
		}
	}
	// if accesskey and the secretkey are blank, get the key from the role
	if Keys.AccessKeyID == "" {

		Keys = getIAMRoleCredentials()
	}

	// if the expiration is set and it's less than 5 minutes in the future, get a new key
	if Keys.Expired() {
		Keys = getIAMRoleCredentials()
	}
}

func getIAMRoleList() []string {
	// Get a list of the roles that are available to this instance
	url := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	resp, _ := client.Do(req)

	// buf := new(bytes.Buffer)
	// buf.ReadFrom(resp.Body)
	// role := buf.String()

	var roles []string

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		roles = append(roles, scanner.Text())
	}
	return roles
}

func getIAMRoleCredentials() *Credentials {

	roles := getIAMRoleList()

	if len(roles) < 1 {
		return &Credentials{}
	}

	// Use the first role in the list
	role := roles[0]

	url := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

	// Create the full URL of the role
	var buffer bytes.Buffer
	buffer.WriteString(url)
	buffer.WriteString(role)
	roleurl := buffer.String()

	// Get the role
	rolereq, _ := http.NewRequest("GET", roleurl, nil)
	roleresp, _ := client.Do(rolereq)
	rolebuf := new(bytes.Buffer)
	rolebuf.ReadFrom(roleresp.Body)

	creds := Credentials{}

	_ = json.Unmarshal(rolebuf.Bytes(), &creds)

	return &creds

}

func augmentRequestQuery(req *http.Request, values url.Values) *http.Request {
	for key, arr := range req.URL.Query() {
		for _, val := range arr {
			values.Set(key, val)
		}
	}

	req.URL.RawQuery = values.Encode()

	return req
}

func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

func hmacSHA1(key []byte, content string) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

func hashSHA256(content []byte) string {
	h := sha256.New()
	h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hashMD5(content []byte) string {
	h := md5.New()
	h.Write(content)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func readAndReplaceBody(req *http.Request) []byte {
	if req.Body == nil {
		return []byte{}
	}
	payload, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return payload
}

func concat(delim string, str ...string) string {
	return strings.Join(str, delim)
}

var now = func() time.Time {
	return time.Now().UTC()
}
