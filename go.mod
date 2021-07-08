module github.com/orange-cloudfoundry/gobis-server

go 1.16

require (
	github.com/cloudfoundry-community/gautocloud v1.1.7
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/orange-cloudfoundry/go-auth-pubtkt v1.0.2 // indirect
	github.com/orange-cloudfoundry/gobis v1.4.3
	github.com/orange-cloudfoundry/gobis-middlewares v1.3.3
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli v1.22.5
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.9.0
