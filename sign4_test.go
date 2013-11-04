package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRequestPreparer(t *testing.T) {
	Convey("Given a plain request with no custom headers", t, func() {
		req := plainRequest(false)

		expectedUnsigned := unsignedRequest(true)
		expectedUnsigned.Header.Set("X-Amz-Date", timestampV4())

		Convey("The necessary, default headers should be appended", func() {
			prepareRequest(req)
			So(req, ShouldResemble, expectedUnsigned)
		})

		Convey("Forward-slash should be appended to URI if not present", func() {
			prepareRequest(req)
			So(req.URL.Path, ShouldEqual, "/")
		})

		Convey("And a set of credentials", func() {
			Keys = testCred

			Convey("It should be signed with an Authorization header", func() {
				actualSigned := Sign4(req)
				actual := actualSigned.Header.Get("Authorization")

				So(actual, ShouldNotBeBlank)
				So(actual, ShouldContainSubstring, "Credential="+testCred.AccessKeyID)
				So(actual, ShouldContainSubstring, "SignedHeaders=")
				So(actual, ShouldContainSubstring, "Signature=")
				So(actual, ShouldContainSubstring, "AWS4")
			})
		})

	})
	Convey("Given a request with custom, necessary headers", t, func() {
		Convey("The custom, necessary headers must not be changed", func() {
			req := unsignedRequest(true)
			prepareRequest(req)
			So(req, ShouldResemble, unsignedRequest(true))
		})
	})
}

func TestSigningTasks(t *testing.T) {
	// http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

	Convey("Given a bogus request and credentials from AWS documentation", t, func() {
		req := unsignedRequest(true)
		meta := new(metadata)

		Convey("(Task 1) The canonical request should be built correctly", func() {
			hashedCanonReq := hashedCanonicalRequest(req, meta)

			So(hashedCanonReq, ShouldEqual, expecting["CanonicalHash"])
		})

		Convey("(Task 2) The string to sign should be built correctly", func() {
			hashedCanonReq := hashedCanonicalRequest(req, meta)
			stringToSign := stringToSignV4(req, hashedCanonReq, meta)

			So(stringToSign, ShouldEqual, expecting["StringToSign"])
		})

		Convey("(Task 3) The version 4 signed signature should be correct", func() {
			hashedCanonReq := hashedCanonicalRequest(req, meta)
			stringToSign := stringToSignV4(req, hashedCanonReq, meta)
			signature := signatureVersion4(testSigningKey(), stringToSign)

			So(signature, ShouldEqual, expecting["SignatureV4"])
		})
	})
}

func TestSignature4Functions(t *testing.T) {

	Convey("The signing key should be properly generated", t, func() {
		expected := []byte{152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43, 171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229, 169, 76, 144, 239, 209, 227, 176, 231}
		actual := testSigningKey()

		So(actual, ShouldResemble, expected)
	})

	Convey("Service and region should be properly extracted from host strings", t, func() {
		s1, r1 := serviceAndRegion("sqs.us-west-2.amazonaws.com")
		So(s1, ShouldEqual, "sqs")
		So(r1, ShouldEqual, "us-west-2")

		s2, r2 := serviceAndRegion("iam.amazonaws.com")
		So(s2, ShouldEqual, "iam")
		So(r2, ShouldEqual, "us-east-1")
	})

	Convey("SHA-256 hashes should be properly hex-encoded (base 16)", t, func() {
		input := "This is... Sparta!!"
		actual := hashSHA256(input)

		So(actual, ShouldEqual, expecting["Sha256Hash"])
	})

	Convey("Given a key and contents", t, func() {
		key := []byte("asdf1234")
		contents := "SmartyStreets was here"

		Convey("HMAC-SHA256 should be properly computed", func() {
			expected := []byte{65, 46, 186, 78, 2, 155, 71, 104, 49, 37, 5, 66, 195, 129, 159, 227, 239, 53, 240, 107, 83, 21, 235, 198, 238, 216, 108, 149, 143, 222, 144, 94}
			actual := hmacSHA256(key, contents)

			So(actual, ShouldResemble, expected)
		})
	})

	Convey("Authorization headers should be built properly", t, func() {
		meta := &metadata{
			algorithm:       "AWS4-HMAC-SHA256",
			credentialScope: "20110909/us-east-1/iam/aws4_request",
			signedHeaders:   "content-type;host;x-amz-date",
		}
		expected := expecting["AuthHeader"] + expecting["SignatureV4"]
		actual := buildAuthHeader(expecting["SignatureV4"], meta)

		So(actual, ShouldEqual, expected)
	})

	Convey("Timestamps should be in the correct format, in UTC time", t, func() {
		actual := timestampV4()

		So(len(actual), ShouldEqual, 16)
		So(actual, ShouldNotContainSubstring, ":")
		So(actual, ShouldNotContainSubstring, "-")
		So(actual, ShouldNotContainSubstring, " ")
		So(actual, ShouldEndWith, "Z")
		So(actual, ShouldContainSubstring, "T")
	})

	Convey("Given an AWS-formatted timestamp", t, func() {
		ts := "20110909T233600Z"

		Convey("The date string should be extracted properly", func() {
			So(tsDate(ts), ShouldEqual, "20110909")
		})
	})

	Convey("Given any request with a body", t, func() {
		req := plainRequest(false)

		Convey("Its body should be read and replaced without differences", func() {
			expected := requestValues.Encode()

			actual1 := readAndReplaceBody(req)
			So(actual1, ShouldEqual, expected)

			actual2 := readAndReplaceBody(req)
			So(actual2, ShouldEqual, expected)
		})
	})

	Convey("Strings should be properly concatenated with a delimiter", t, func() {
		So(concat("\n", "Test1", "Test2"), ShouldEqual, "Test1\nTest2")
		So(concat(".", "Test1"), ShouldEqual, "Test1")
		So(concat("\t", "1", "2", "3", "4"), ShouldEqual, "1\t2\t3\t4")
	})
}

var requestValues = &url.Values{
	"Action":  []string{"ListUsers"},
	"Version": []string{"2010-05-08"},
}

func plainRequest(trailingSlash bool) *http.Request {
	url := "http://iam.amazonaws.com"
	body := strings.NewReader(requestValues.Encode())

	if trailingSlash {
		url += "/"
	}

	req, err := http.NewRequest("POST", url, body)

	if err != nil {
		panic(err)
	}

	return req
}

func unsignedRequest(trailingSlash bool) *http.Request {
	req := plainRequest(trailingSlash)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", "20110909T233600Z")
	return req
}

var testCred = &Credentials{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

var expecting = map[string]string{
	"CanonicalHash": "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2",
	"StringToSign": `AWS4-HMAC-SHA256
20110909T233600Z
20110909/us-east-1/iam/aws4_request
3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2`,
	"SignatureV4": "ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c",
	"Sha256Hash":  "5c81a4ef1172e89b1a9d575f4cd82f4ed20ea9137e61aa7f1ab936291d24e79a",
	"AuthHeader":  "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=",
}

func testSigningKey() []byte {
	return signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20110909", "us-east-1", "iam")
}
