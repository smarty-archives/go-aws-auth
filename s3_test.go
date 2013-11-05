package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"testing"
)

func TestSignatureS3(t *testing.T) {
	// http://docs.aws.amazon.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html

	Convey("Given a GET request to Amazon S3", t, func() {
		req, _ := http.NewRequest("GET", "https://bucketname.s3.amazonaws.com/photos/puppy.jpg", nil)
		req.Header.Set("X-Amz-Meta-Something", "more foobar")
		req.Header.Set("X-Amz-Date", "foobar")
		req.Header.Set("X-Foobar", "nanoo-nanoo")

		Convey("The CanonicalizedAmzHeaders should be built properly", func() {
			actual := canonicalAmzHeadersS3(req)
			So(actual, ShouldEqual, expectedCanonAmzHeadersS3)
		})

		Convey("The CanonicalizedResource should be built properly", func() {
			actual := canonicalResourceS3(req)
			So(actual, ShouldEqual, expectedCanonResourceS3)
		})
	})
}

var (
	testCredS3                = &Credentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	expectedCanonAmzHeadersS3 = "x-amz-date:foobar\nx-amz-meta-something:more foobar\n"
	expectedCanonResourceS3   = "/bucketname/photos/puppy.jpg"
)
