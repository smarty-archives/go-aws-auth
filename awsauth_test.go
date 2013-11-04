package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestIntegration(t *testing.T) {
	Convey("Given real credentials from environment variables", t, func() {
		Convey("A request to IAM should succeed", nil)

		Convey("A request to S3 should succeed", nil)

		Convey("A request to EC2 should succeed", func() {
			req := newRequest("GET", "https://ec2.amazonaws.com", url.Values{
				"Action": []string{"DescribeInstances"},
			})
			resp := sign2AndDo(req)

			if !envCredentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})

		Convey("A request to SQS should succeed", func() {
			req := newRequest("POST", "https://sqs.us-west-2.amazonaws.com", url.Values{
				"Action": []string{"ListQueues"},
			})
			resp := sign4AndDo(req)

			if !envCredentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})

	})
}

func envCredentialsSet() bool {
	return os.Getenv(envAccessKeyID) != "" && os.Getenv(envSecretAccessKey) != ""
}

func newRequest(method string, url string, v url.Values) *http.Request {
	req, _ := http.NewRequest(method, url, strings.NewReader(v.Encode()))
	return req
}

func sign2AndDo(req *http.Request) *http.Response {
	Sign2(req)
	resp, _ := client.Do(req)
	return resp
}

func sign4AndDo(req *http.Request) *http.Response {
	Sign4(req)
	resp, _ := client.Do(req)
	return resp
}

var client = &http.Client{}
