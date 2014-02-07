package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestSignature2(t *testing.T) {
	// http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html

	Convey("Given bogus credentials", t, func() {
		Keys = testCredV2

		// Mock time
		now = func() time.Time {
			parsed, _ := time.Parse(timeFormatV2, exampleReqTsV2)
			return parsed
		}

		Convey("Given a plain request that is unprepared", func() {
			req := test_plainRequestV2()

			Convey("The request should be prepared to be signed", func() {
				expectedUnsigned := test_unsignedRequestV2()
				prepareRequestV2(req)
				So(req, ShouldResemble, expectedUnsigned)
			})
		})

		Convey("Given a prepared, but unsigned, request", func() {
			req := test_unsignedRequestV2()

			Convey("The canonical query string should be correct", func() {
				actual := canonicalQueryStringV2(req)
				expected := canonicalQsV2
				So(actual, ShouldEqual, expected)
			})

			Convey("The absolute path should be extracted correctly", func() {
				So(req.URL.Path, ShouldEqual, "/")
			})

			Convey("The string to sign should be well-formed", func() {
				actual := stringToSignV2(req)
				So(actual, ShouldEqual, expectedStringToSignV2)
			})

			Convey("The resulting signature should be correct", func() {
				actual := signatureV2(stringToSignV2(req))
				So(actual, ShouldEqual, "i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf/Mj6vPxyYIs=")
			})

			Convey("The final signed request should be correctly formed", func() {
				Sign2(req)
				actual := req.URL.String()
				So(actual, ShouldResemble, expectedFinalUrlV2)
			})
		})
	})
}

func test_plainRequestV2() *http.Request {
	values := url.Values{}
	values.Set("Action", "DescribeJobFlows")
	values.Set("Version", "2009-03-31")

	url := baseUrlV2 + "?" + values.Encode()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	return req
}

func test_unsignedRequestV2() *http.Request {
	req := test_plainRequestV2()
	newUrl, _ := url.Parse(baseUrlV2 + "/?" + canonicalQsV2)
	req.URL = newUrl
	return req
}

var (
	testCredV2             = &Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	exampleReqTsV2         = "2011-10-03T15:19:30"
	baseUrlV2              = "https://elasticmapreduce.amazonaws.com"
	canonicalQsV2          = "AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Action=DescribeJobFlows&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-10-03T15%3A19%3A30&Version=2009-03-31"
	expectedStringToSignV2 = "GET\nelasticmapreduce.amazonaws.com\n/\n" + canonicalQsV2
	expectedFinalUrlV2     = baseUrlV2 + "/?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Action=DescribeJobFlows&Signature=i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf%2FMj6vPxyYIs%3D&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-10-03T15%3A19%3A30&Version=2009-03-31"
)
