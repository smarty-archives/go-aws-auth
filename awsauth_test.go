package awsauth

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
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
			// TODO -- Uh oh, EC2 only supports Signature Version 2. Hmmm.
			req := newRequest("https://ec2.amazonaws.com", url.Values{
				"Action": []string{"DescribeInstances"},
			})
			resp := signAndDo(req)

			if !envCredentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				b, _ := ioutil.ReadAll(resp.Body)
				fmt.Println(string(b))
			}
		})

		Convey("A request to SQS should succeed", func() {
			req := newRequest("https://sqs.us-west-2.amazonaws.com", url.Values{
				"Action": []string{"ListQueues"},
			})
			resp := signAndDo(req)

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

func newRequest(url string, v url.Values) *http.Request {
	req, _ := http.NewRequest("POST", url, strings.NewReader(v.Encode()))
	return req
}

func signAndDo(req *http.Request) *http.Response {
	Sign4(req)
	resp, _ := client.Do(req)
	return resp
}

var client = &http.Client{}
