package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestSignature3(t *testing.T) {
	// http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/RESTAuthentication.html
	// http://docs.aws.amazon.com/ses/latest/DeveloperGuide/query-interface-authentication.html

	Convey("Given bogus credentials", t, func() {
		Keys = testCredV3

		// Mock time
		now = func() time.Time {
			parsed, _ := time.Parse(timeFormatV3, exampleReqTsV3)
			return parsed
		}

		Convey("Given a plain request that is unprepared", func() {
			req := test_plainRequestV3()

			Convey("The request should be prepared to be signed", func() {
				expectedUnsigned := test_unsignedRequestV3()
				prepareRequestV3(req)
				So(req, ShouldResemble, expectedUnsigned)
			})
		})

		Convey("Given a prepared, but unsigned, request", func() {
			req := test_unsignedRequestV3()

			Convey("The absolute path should be extracted correctly", func() {
				So(req.URL.Path, ShouldEqual, "/")
			})

			Convey("The string to sign should be well-formed", func() {
				actual := stringToSignV3(req)
				So(actual, ShouldEqual, expectedStringToSignV3)
			})

			Convey("The resulting signature should be correct", func() {
				actual := signatureV3(stringToSignV3(req))
				So(actual, ShouldEqual, "PjAJ6buiV6l4WyzmmuwtKE59NJXVg5Dr3Sn4PCMZ0Yk=")
			})

			Convey("The final signed request should be correctly formed", func() {
				Sign3(req)
				actual := req.Header.Get("X-Amzn-Authorization")
				So(actual, ShouldResemble, expectedAuthHeaderV3)
			})
		})
	})
}

func test_plainRequestV3() *http.Request {
	values := url.Values{}
	values.Set("Action", "GetSendStatistics")
	values.Set("Version", "2010-12-01")

	url := baseUrlV3 + "/?" + values.Encode()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	return req
}

func test_unsignedRequestV3() *http.Request {
	req := test_plainRequestV3()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("x-amz-date", exampleReqTsV3)
	req.Header.Set("Date", exampleReqTsV3)
	req.Header.Set("x-amz-nonce", "")
	return req
}

var (
	testCredV3             = &Credentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""}
	exampleReqTsV3         = "Thu, 14 Aug 2008 17:08:48 GMT"
	baseUrlV3              = "https://email.us-east-1.amazonaws.com"
	expectedStringToSignV3 = exampleReqTsV3
	expectedAuthHeaderV3   = "AWS3-HTTPS AWSAccessKeyId=" + testCredV3.AccessKeyID + ", Algorithm=HmacSHA256, Signature=PjAJ6buiV6l4WyzmmuwtKE59NJXVg5Dr3Sn4PCMZ0Yk="
)
