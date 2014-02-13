package awsauth

import (
	"net/http"
	"testing"
	"time"
	. "github.com/smartystreets/goconvey/convey"
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

	Convey("Given a GET request for a resource on S3 for query string authentication", t, func() {
		Keys = testCredS3
		req, _ := http.NewRequest("GET", "https://johnsmith.s3.amazonaws.com/johnsmith/photos/puppy.jpg", nil)

		now = func() time.Time {
			parsed, _ := time.Parse(timeFormatS3, exampleReqTsS3)
			return parsed
		}

		Convey("The string to sign should be correct", func() {
			actual := stringToSignS3Url("GET", now(), req.URL.Path)
			So(actual, ShouldEqual, expectedStringToSignS3Url)
		})

		Convey("The signature of string to sign should be correct", func() {
			actual := signatureS3(expectedStringToSignS3Url)
			So(actual, ShouldEqual, "R2K/+9bbnBIbVDCs7dqlz3XFtBQ=")
		})
	})
}

func TestS3STSRequestPreparer(t *testing.T) {
	Convey("Given a plain request with no custom headers", t, func() {
		req := test_plainRequestS3()

		Convey("And a set of credentials with an STS token", func() {
			Keys = testCredS3WithSTS

			Convey("It should include an X-Amz-Security-Token when the request is signed", func() {
				actualSigned := SignS3(req)
				actual := actualSigned.Header.Get("X-Amz-Security-Token")

				So(actual, ShouldNotBeBlank)
				So(actual, ShouldEqual, testCredS3WithSTS.SecurityToken)

			})
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
	testCredS3 = &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	testCredS3WithSTS = &Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		SecurityToken:   "AQoDYXdzEHcaoAJ1Aqwx1Sum0iW2NQjXJcWlKR7vuB6lnAeGBaQnjDRZPVyniwc48ml5hx+0qiXenVJdfusMMl9XLhSncfhx9Rb1UF8IAOaQ+CkpWXvoH67YYN+93dgckSVgVEBRByTl/BvLOZhe0ii/pOWkuQtBm5T7lBHRe4Dfmxy9X6hd8L3FrWxgnGV3fWZ3j0gASdYXaa+VBJlU0E2/GmCzn3T+t2mjYaeoInAnYVKVpmVMOrh6lNAeETTOHElLopblSa7TAmROq5xHIyu4a9i2qwjERTwa3Yk4Jk6q7JYVA5Cu7kS8wKVml8LdzzCTsy+elJgvH+Jf6ivpaHt/En0AJ5PZUJDev2+Y5+9j4AYfrmXfm4L73DC1ZJFJrv+Yh+EXAMPLE=",
	}

	expectedCanonAmzHeadersS3 = "x-amz-date:foobar\nx-amz-meta-something:more foobar\n"
	expectedCanonResourceS3   = "/johnsmith/photos/puppy.jpg"
	expectedStringToSignS3    = "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg"
	expectedStringToSignS3Url = "GET\n\n\n1175024202\n/johnsmith/photos/puppy.jpg"
	exampleReqTsS3            = "Tue, 27 Mar 2007 19:36:42 +0000"
)
