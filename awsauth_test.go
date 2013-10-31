package awsauth

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestSigningFunctions(t *testing.T) {
	Convey("Given a bogus request and credentials from AWS documentation", t, func() {
		Convey("(Task 1) The canonical request should be built correctly", nil)
		Convey("(Task 2) The string to sign should be built correctly", nil)
		Convey("(Task 3) The version 4 signed signature should be correct", nil)
		Convey("The resulting signed request should be correct", nil)
	})
}
func TestIntegration(t *testing.T) {
	Convey("Given real credentials from environment variables", t, func() {
		Convey("A request to IAM should succeed", nil)
		Convey("A request to S3 should succeed", nil)
		Convey("A request to EC2 should succeed", nil)
		Convey("A request to SQS should succeed", nil)
	})
}
