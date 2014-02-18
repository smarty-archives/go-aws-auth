package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIntegration(t *testing.T) {
	Convey("Given real credentials from environment variables", t, func() {
		Convey("A request (with out-of-order query string) with to IAM should succeed (assuming Administrator Access policy)", func() {
			req := newRequest("GET", "https://iam.amazonaws.com/?Version=2010-05-08&Action=ListRoles", url.Values{})
			resp := sign4AndDo(req)

			if !credentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})

		Convey("A request to S3 should succeed", func() {
			req, _ := http.NewRequest("GET", "https://s3.amazonaws.com", nil)
			resp := signS3AndDo(req)

			if !credentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})

		Convey("A request to EC2 should succeed", func() {
			req := newRequest("GET", "https://ec2.amazonaws.com", url.Values{
				"Action": []string{"DescribeInstances"},
			})
			resp := sign2AndDo(req)

			if !credentialsSet() {
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

			if !credentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})

		Convey("A request to SES should succeed", func() {
			req := newRequest("GET", "https://email.us-east-1.amazonaws.com/?Action=GetSendStatistics", url.Values{})
			resp := sign3AndDo(req)

			if !credentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})

		Convey("A request to Route 53 should succeed", func() {
			req := newRequest("GET", "https://route53.amazonaws.com/2013-04-01/hostedzone?maxitems=1", url.Values{})
			resp := sign3AndDo(req)

			if !credentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})

		Convey("A request to SimpleDB should succeed", func() {
			req := newRequest("GET", "https://sdb.amazonaws.com/?Action=ListDomains&Version=2009-04-15", url.Values{})
			resp := sign2AndDo(req)

			if !credentialsSet() {
				SkipSo(resp.StatusCode, ShouldEqual, http.StatusOK)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}
		})
	})
}

func TestSign(t *testing.T) {
	Convey("Requests to services using Version 2 should be signed accordingly", t, func() {
		reqs := []*http.Request{
			newRequest("GET", "https://ec2.amazonaws.com", url.Values{}),
			newRequest("GET", "https://elasticache.amazonaws.com/", url.Values{}),
		}
		for _, req := range reqs {
			signedReq := Sign(req)
			So(signedReq.URL.Query().Get("SignatureVersion"), ShouldEqual, "2")
		}
	})

	Convey("Requests to services using Version 3 should be signed accordingly", t, func() {
		reqs := []*http.Request{
			newRequest("GET", "https://route53.amazonaws.com", url.Values{}),
			newRequest("GET", "https://email.us-east-1.amazonaws.com/", url.Values{}),
		}
		for _, req := range reqs {
			signedReq := Sign(req)
			So(signedReq.Header.Get("X-Amzn-Authorization"), ShouldNotBeBlank)
		}
	})

	Convey("Requests to services using Version 4 should be signed accordingly", t, func() {
		reqs := []*http.Request{
			newRequest("POST", "https://sqs.amazonaws.com/", url.Values{}),
			newRequest("GET", "https://iam.amazonaws.com", url.Values{}),
		}
		for _, req := range reqs {
			signedReq := Sign(req)
			So(signedReq.Header.Get("Authorization"), ShouldContainSubstring, ", Signature=")
		}
	})

	Convey("Requests to S3 should be signed accordingly", t, func() {
		req := newRequest("GET", "https://johnsmith.s3.amazonaws.com", url.Values{})
		signedReq := Sign(req)

		So(signedReq.Header.Get("Authorization"), ShouldStartWith, "AWS ")
		So(signedReq.Header.Get("Authorization"), ShouldContainSubstring, ":")
	})
}

func TestExpiration(t *testing.T) {
	var c = &Credentials{}

	Convey("Credentials without an expiration can't expire", t, func() {
		So(c.expired(), ShouldBeFalse)
	})

	Convey("Credentials that expire in 5 minutes aren't expired", t, func() {
		c.Expiration = time.Now().Add(5 * time.Minute)
		So(c.expired(), ShouldBeFalse)
	})

	Convey("Credentials that expire in 1 minute are expired", t, func() {
		c.Expiration = time.Now().Add(1 * time.Minute)
		So(c.expired(), ShouldBeTrue)
	})

	Convey("Credentials that expired in 2 hours ago are expired", t, func() {
		c.Expiration = time.Now().Add(-2 * time.Hour)
		So(c.expired(), ShouldBeTrue)
	})
}

func credentialsSet() bool {
	checkKeys()
	if Keys.AccessKeyID == "" {
		return false
	} else {
		return true
	}
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

func sign3AndDo(req *http.Request) *http.Response {
	Sign3(req)
	resp, _ := client.Do(req)
	return resp
}

func sign4AndDo(req *http.Request) *http.Response {
	Sign4(req)
	resp, _ := client.Do(req)
	return resp
}

func signS3AndDo(req *http.Request) *http.Response {
	SignS3(req)
	resp, _ := client.Do(req)
	return resp
}

var client = &http.Client{}
