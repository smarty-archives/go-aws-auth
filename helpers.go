package awsauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

func hashSHA256(content string) string {
	h := sha256.New()
	h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func timestamp() string {
	t := time.Now().UTC().Format(time.RFC3339)
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

func hmacSHA256(key, content string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(content))
	return string(mac.Sum(nil))
}
