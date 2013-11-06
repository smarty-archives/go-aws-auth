go-aws-auth
===========

Go-AWS-Auth aims to be a comprehensive, lightweight library for signing requests to Amazon Web Services.

With Go-AWS-Auth, you need not take any thought about authenticating with AWS. Simply build your requests with the needed parameters and call `awsauth.Sign(req)` before making your request to AWS.

Go-AWS-Auth is intended to keep the ball in your court when actually performing the request, and is concerned merely with tackling the (rather involved) process of signing the request with your credentials.



### Supported signing mechanisms

- Signed Signature Version 2
- Signed Signature Version 4
- Custom S3 HTTP Scheme


### Install

Go get it:

	$ go get github.com/smartystreets/go-aws-auth
	
Then import it:

	import "github.com/smartystreets/awsauth"


### Using your AWS Credentials

You can do it two ways.

1. **Recommended:** Set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables with your credentials. The library will automatically detect and use them.

2. You can set `awsauth.Keys` with hard-coded credentials (for testing or spike code): `awsauth.Keys = &awsauth.Credentials{"Access Key ID", "Secret Access Key"}` 

Setting the credentials manually will override environment variables.



### Signing requests

Once your credentials are set up, simply make a plain request for AWS, have it signed, then perform the request as you desire.

```go
url := "https://iam.amazonaws.com/?Action=ListRoles&Version=2010-05-08"
client := &http.Client{}

req, err := http.NewRequest("GET", url, nil)

awsauth.Sign(req)	// Automatically chooses the best signing mechanism for the service

resp, err := client.Do(req)
```



### Contributing

This library isn't quite complete (yet) but should work well for most common AWS interactions. Please feel free to contribute by forking, opening issues, submitting pull requests, etc.
