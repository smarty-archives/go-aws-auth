package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"testing"
	"time"
)

func TestSignatureS3(t *testing.T) {
	// http://docs.aws.amazon.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html

	Convey("Given a GET request to Amazon S3", t, func() {
		Keys = testCredS3
		req := test_plainRequestS3()

		// Mock time
		now = func() time.Time {
			parsed, _ := time.Parse(timeFormatS3, exampleReqTsS3)
			return parsed
		}

		Convey("The request should be prepared with a Date header", func() {
			prepareRequestS3(req)
			So(req.Header.Get("Date"), ShouldEqual, exampleReqTsS3)
		})

		Convey("The CanonicalizedAmzHeaders should be built properly", func() {
			req2 := test_headerRequestS3()
			actual := canonicalAmzHeadersS3(req2)
			So(actual, ShouldEqual, expectedCanonAmzHeadersS3)
		})

		Convey("The CanonicalizedResource should be built properly", func() {
			actual := canonicalResourceS3(req)
			So(actual, ShouldEqual, expectedCanonResourceS3)
		})

		Convey("The string to sign should be correct", func() {
			actual := stringToSignS3(req)
			So(actual, ShouldEqual, expectedStringToSignS3)
		})

		Convey("The final signature string should be exactly correct", func() {
			actual := signatureS3(stringToSignS3(req))
			So(actual, ShouldEqual, "bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
		})
	})
}

func test_plainRequestS3() *http.Request {
	req, _ := http.NewRequest("GET", "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg", nil)
	return req
}

func test_headerRequestS3() *http.Request {
	req := test_plainRequestS3()
	req.Header.Set("X-Amz-Meta-Something", "more foobar")
	req.Header.Set("X-Amz-Date", "foobar")
	req.Header.Set("X-Foobar", "nanoo-nanoo")
	return req
}

var (
	testCredS3                = &Credentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""}
	expectedCanonAmzHeadersS3 = "x-amz-date:foobar\nx-amz-meta-something:more foobar\n"
	expectedCanonResourceS3   = "/johnsmith/photos/puppy.jpg"
	expectedStringToSignS3    = "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg"
	exampleReqTsS3            = "Tue, 27 Mar 2007 19:36:42 +0000"
)
