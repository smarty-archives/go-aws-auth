package awsauth

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

func signatureS3(stringToSign string) string {
	fmt.Println("TODO")
	return ""
}

func canonicalAmzHeadersS3(req *http.Request) string {
	var headers []string

	for header := range req.Header {
		standardized := strings.ToLower(strings.TrimSpace(header))
		if strings.HasPrefix(standardized, "x-amz") {
			headers = append(headers, standardized)
		}
	}

	sort.Strings(headers)

	for i, header := range headers {
		headers[i] = header + ":" + strings.Replace(req.Header.Get(header), "\n", " ", -1)
	}

	return strings.Join(headers, "\n") + "\n"
}

func canonicalResourceS3(req *http.Request) string {
	res := ""

	if isS3VirtualHostedStyle(req) {
		_, bucketname := serviceAndRegion(req.Host)
		res += "/" + bucketname
	}

	res += req.URL.Path

	for _, subres := range strings.Split(subresourcesS3, ",") {
		if strings.HasPrefix(req.URL.RawQuery, subres) {
			res += "?" + subres
		}
	}

	return res
}

func prepareRequestS3(req *http.Request) *http.Request {
	// TODO: test
	if req.URL.Path == "" {
		req.URL.Path += "/"
	}
	return req
}

func isS3VirtualHostedStyle(req *http.Request) bool {
	service, _ := serviceAndRegion(req.Host)
	return service == "s3" && strings.Count(req.Host, ".") == 3
}

func timestampS3() string {
	return now().Format(timeFormatS3)
}

const (
	timeFormatS3   = time.RFC1123Z
	subresourcesS3 = "acl,lifecycle,location,logging,notification,partNumber,policy,requestPayment,torrent,uploadId,uploads,versionId,versioning,versions,website"
)
