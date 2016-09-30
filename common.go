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
	"errors"
	"fmt"
	"github.com/go-ini/ini"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type location struct {
	ec2     bool
	checked bool
}

var loc *location

// serviceAndRegion parsers a hostname to find out which ones it is.
// http://docs.aws.amazon.com/general/latest/gr/rande.html
func serviceAndRegion(host string) (service string, region string) {
	// These are the defaults if the hostname doesn't suggest something else
	region = "us-east-1"
	service = "s3"

	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		// Either service.region.amazonaws.com or virtual-host.region.amazonaws.com
		if parts[1] == "s3" {
			service = "s3"
		} else if strings.HasPrefix(parts[1], "s3-") {
			region = parts[1][3:]
			service = "s3"
		} else {
			service = parts[0]
			region = parts[1]
		}
	} else if len(parts) == 5 {
		if parts[1] == "execute-api" { //TODO: is this the only service?
			// API Gateway ("execute-api") has form 1234abcd56.execute-api.us-east-1.amazonaws.com
			service = parts[1]
			region = parts[2]
		} else {
			service = parts[2]
			region = parts[1]
		}
	} else {
		// Either service.amazonaws.com or s3-region.amazonaws.com
		if strings.HasPrefix(parts[0], "s3-") {
			region = parts[0][3:]
		} else {
			service = parts[0]
		}
	}

	if region == "external-1" {
		region = "us-east-1"
	}

	return
}

// newKeys produces a set of credentials based on the environment
func newKeys() (newCredentials Credentials) {
	var err error
	if newCredentials, err = envRetrieve(); err == nil {
		return
	}

	if newCredentials, err = profileRetrieve(); err == nil {
		return
	}

	// If there is no Access Key and you are on EC2, get the key from the role
	if (newCredentials.AccessKeyID == "" || newCredentials.SecretAccessKey == "") && onEC2() {
		newCredentials = *getIAMRoleCredentials()
	}

	// If the key is expiring, get a new key
	if newCredentials.expired() && onEC2() {
		newCredentials = *getIAMRoleCredentials()
	}

	return
}

// Retrieves credentials from the ENV variables
func envRetrieve() (Credentials, error) {
	id := os.Getenv("AWS_ACCESS_KEY_ID")
	if id == "" {
		id = os.Getenv("AWS_ACCESS_KEY")
	}

	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if secret == "" {
		secret = os.Getenv("AWS_SECRET_KEY")
	}

	if id == "" {
		return Credentials{}, errors.New("No AWS_ACCESS_KEY_ID set")
	}

	if secret == "" {
		return Credentials{}, errors.New("No AWS_SECRET_ACCESS_KEY set")
	}

	return Credentials{
		AccessKeyID:     id,
		SecretAccessKey: secret,
		SecurityToken:   os.Getenv("AWS_SESSION_TOKEN"),
	}, nil
}

// Retrieves credentials from the ~/.aws/credentials directory
func profileRetrieve() (Credentials, error) {
	filename := ""
	if filename = os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); filename == "" {
		homeDir := os.Getenv("HOME") // *nix
		if homeDir == "" {           // Windows
			homeDir = os.Getenv("USERPROFILE")
		}
		if homeDir == "" {
			return Credentials{}, errors.New("Cannot find home directory")
		}

		filename = filepath.Join(homeDir, ".aws", "credentials")
	}

	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = "default"
	}

	config, err := ini.Load(filename)
	if err != nil {
		return Credentials{}, errors.New("failed to load shared credentials file")
	}
	iniProfile, err := config.GetSection(profile)
	if err != nil {
		return Credentials{}, errors.New("failed to get profile")
	}

	id, err := iniProfile.GetKey("aws_access_key_id")
	if err != nil {
		return Credentials{}, errors.New(fmt.Sprintf("shared credentials %s in %s did not contain aws_access_key_id", profile, filename))
	}

	secret, err := iniProfile.GetKey("aws_secret_access_key")
	if err != nil {
		return Credentials{}, errors.New(fmt.Sprintf("shared credentials %s in %s did not contain aws_secret_access_key", profile, filename))
	}

	// Default to empty string if not found
	token := iniProfile.Key("aws_session_token")

	return Credentials{
		AccessKeyID:     id.String(),
		SecretAccessKey: secret.String(),
		SecurityToken:   token.String(),
	}, nil
}

// checkKeys gets credentials depending on if any were passed in as an argument
// or it makes new ones based on the environment.
func chooseKeys(cred []Credentials) Credentials {
	if len(cred) == 0 {
		return newKeys()
	} else {
		return cred[0]
	}
}

// onEC2 checks to see if the program is running on an EC2 instance.
// It does this by looking for the EC2 metadata service.
// This caches that information in a struct so that it doesn't waste time.
func onEC2() bool {
	if loc == nil {
		loc = &location{}
	}
	if !(loc.checked) {
		c, err := net.DialTimeout("tcp", "169.254.169.254:80", time.Millisecond*100)

		if err != nil {
			loc.ec2 = false
		} else {
			c.Close()
			loc.ec2 = true
		}
		loc.checked = true
	}

	return loc.ec2
}

// getIAMRoleList gets a list of the roles that are available to this instance
func getIAMRoleList() []string {

	var roles []string
	url := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

	client := &http.Client{}

	request, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return roles
	}

	response, err := client.Do(request)

	if err != nil {
		return roles
	}
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
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
	roleURL := buffer.String()

	// Get the role
	roleRequest, err := http.NewRequest("GET", roleURL, nil)

	if err != nil {
		return &Credentials{}
	}

	client := &http.Client{}
	roleResponse, err := client.Do(roleRequest)

	if err != nil {
		return &Credentials{}
	}
	defer roleResponse.Body.Close()

	roleBuffer := new(bytes.Buffer)
	roleBuffer.ReadFrom(roleResponse.Body)

	credentials := Credentials{}

	err = json.Unmarshal(roleBuffer.Bytes(), &credentials)

	if err != nil {
		return &Credentials{}
	}

	return &credentials

}

func augmentRequestQuery(request *http.Request, values url.Values) *http.Request {
	for key, array := range request.URL.Query() {
		for _, value := range array {
			values.Set(key, value)
		}
	}

	request.URL.RawQuery = values.Encode()

	return request
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

func readAndReplaceBody(request *http.Request) []byte {
	if request.Body == nil {
		return []byte{}
	}
	payload, _ := ioutil.ReadAll(request.Body)
	request.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return payload
}

func concat(delim string, str ...string) string {
	return strings.Join(str, delim)
}

var now = func() time.Time {
	return time.Now().UTC()
}

func normuri(uri string) string {
	parts := strings.Split(uri, "/")
	for i := range parts {
		parts[i] = encodePathFrag(parts[i])
	}
	return strings.Join(parts, "/")
}

func encodePathFrag(s string) string {
	hexCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			hexCount++
		}
	}
	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c) {
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		} else {
			t[j] = c
			j++
		}
	}
	return string(t)
}

func shouldEscape(c byte) bool {
	if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
		return false
	}
	if '0' <= c && c <= '9' {
		return false
	}
	if c == '-' || c == '_' || c == '.' || c == '~' {
		return false
	}
	return true
}

func normquery(v url.Values) string {
	queryString := v.Encode()

	// Go encodes a space as '+' but Amazon requires '%20'. Luckily any '+' in the
	// original query string has been percent escaped so all '+' chars that are left
	// were originally spaces.

	return strings.Replace(queryString, "+", "%20", -1)
}
