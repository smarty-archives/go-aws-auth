package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestHelperFunctions(t *testing.T) {

	Convey("SHA-256 hashes should be properly hex-encoded (base 16)", t, func() {
		input := "This is... Sparta!!"
		expected := "5c81a4ef1172e89b1a9d575f4cd82f4ed20ea9137e61aa7f1ab936291d24e79a"
		actual := hashSHA256(input)

		So(actual, ShouldEqual, expected)
	})

	Convey("Given a key and contents", t, func() {
		key := "asdf1234"
		contents := "SmartyStreets was here"

		Convey("HMAC-SHA256 should be properly computed", func() {
			expected := "412eba4e029b476831250542c3819fe3ef35f06b5315ebc6eed86c958fde905e"

			So(hmacSHA256(key, contents), ShouldEqual, expected)
		})
	})

	Convey("Timestamps should be in the correct format, in UTC time", t, func() {
		actual := timestamp()

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

	Convey("Strings should be properly concatenated with a delimiter", t, func() {
		So(concat("\n", "Test1", "Test2"), ShouldEqual, "Test1\nTest2")
		So(concat(".", "Test1"), ShouldEqual, "Test1")
		So(concat("\t", "1", "2", "3", "4"), ShouldEqual, "1\t2\t3\t4")
	})

}
