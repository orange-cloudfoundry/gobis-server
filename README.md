# Gobis-server

Create a [gobis](https://github.com/orange-cloudfoundry/gobis) server based on a config file.

The standalone server will make available all middlewares you can found in [gobis-middlewares](https://github.com/orange-cloudfoundry/gobis-middlewares)

**Note**: To enable them in your route see parameters to set on each ones

## Installation

```
go get github/orange-cloudfoundry/gobis-server
```

If you set your `PATH` with `$GOPATH/bin/` you should have now a `gobis-server` binary available, this is the standalone server.

## Commands

```
NAME:
   gobis-server - Create a gobis server based on a config file

USAGE:
   gobis-server [global options]

VERSION:
   1.1.1

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --config-path value, -c value     Path to the config file (default: "gobis-config.yml")
   --cert value                      Path to a cert file or a cert content to enable https server (default: "server.crt")
   --key value                       Path to a key file or a key content to enable https server (default: "server.key")
   --log-level value, -l value       Log level to use (default: "info")
   --forward-url value, -f value     If set all non-found url by gobis will be forwarded to this url
   --log-json, -j                    Write log in json
   --no-color                        Logger will not display colors
   --lets-encrypt value, --le value  If set server will use a certificate generated with let's encypt, value should be your domain(s) (e.g.: --lets-encrypt=example.com[,seconddomain.com]). Host and port will be overwritten to use 0.0.0.0:443
   --help, -h                        show help
   --version, -v                     print the version
```

## Usage

There is two different usage:
1. [In local](#in-local)
2. [In a cloud](#in-a-cloud) through [gautocloud](https://github.com/cloudfoundry-community/gautocloud) (Run with ease gobis on: Kubernetes, CloudFoundry or Heroku)

### In local

1. Create a `gobis-config.yml` file where you want to run your server, following this schema:

```yaml
# Host where server should listen (default to 0.0.0.0) 
host: 127.0.0.1 # you can either set 0.0.0.0
# Port where server should listen, if empty it will look for PORT env var and if not found it will be listen on 9080
port: 8080
# List of headers which cannot be removed by `sensitive_headers`
protected_headers: []
# Set the path where all path from route should start (e.g.: if set to `/root` request for the next route will be localhost/root/app)
start_path: ""
routes:
  # Name of your route
- name: myapi
  # Path which gobis handler should listen to
  # You can use globs:
  #   - appending /* will only make requests available in first level of upstream
  #   - appending /** will pass everything to upstream
  path: /app/**
  # Upstream url where all request will be redirected
  # Query parameters can be passed, e.g.: http://localhost?param=1
  # User and password are given as basic auth too (this is not recommended to use it), e.g.: http://user:password@localhost
  url: http://www.mocky.io/v2/595625d22900008702cd71e8
  # List of headers which should not be sent to upstream
  sensitive_headers: []
  # An url to an http proxy to make requests to upstream pass to this
  http_proxy: ""
  # An url to an https proxy to make requests to upstream pass to this
  https_proxy: ""
  # Force to never use proxy even proxy from environment variables
  no_proxy: false
  # By default response from upstream are buffered, it can be issue when sending big files
  # Set to true to stream response
  no_buffer: false
  # Set to true to not send X-Forwarded-* headers to upstream
  remove_proxy_headers: false
  #  An url to an http proxy to make request to upstream pass to this
  methods: []
  # Set to true to not check ssl certificates from upstream (not recommended)
  insecure_skip_verify: false
  # Set to true to see errors on web page when there is a panic error on gobis
  show_error: false
  # It was made to pass arbitrary params to use it after in gobis middlewares
  # Here you can set cors parameters for cors middleware (see doc relative to middlewares)
  extra_params:
    cors:
      max_age: 12
      allowed_origins:
      - http://localhost
```

2. Run `gobis` in your terminal and server is now started

### In a cloud

**Note**: If a gobis config file exists routes, protected headers, start path and host will be merged against the service configuration.
  
#### On CloudFoundry as an a

1. Create a cups service named `.*gobis-config` with the same credentials set in yaml, example:
```json
{
  "protected_headers": ["x-header-one"],
  "routes": [
    {
      "name": "app",
      "path": "/**",
      "url": "http://www.mocky.io/v2/595625d22900008702cd71e8",
      "show_error": true,
      "no_buffer": false
    }
  ]
}
```
2. Bind it to your gobis instance

----

You can either create a configuration to make your app be used as a route service, this how to to do this.

Your configuration should use `forwarded_header` set to `X-CF-Forwarded-Url`.

Url can be omitted but if you set it to the cloud foundry route where you want to redirect it will possible to create multiple gobis routes for different cloud foundry app.
 
Example of configuration:
```json
{
  "protected_headers": ["x-header-one"],
  "routes": [
    {
      "name": "my-cf-app",
      "path": "/**",
      "url": "http://my_cf_app_under_gobis.external.domain.cf",
      "forwarded_header": "X-CF-Forwarded-Url",
      "show_error": true,
      "no_buffer": false
    }
  ]
}
```

you can now create an user provided route service (`cf cups to-gobis -r https://gobis.external.domain.cf`) and bind it to 
your app route which will be under gobis (`cf bind-route-service external.domain.cf to-gobis --hostname my_cf_app_under_gobis`)

#### On Heroku or Kubernetes

1. Create an env var or service named `.*GOBIS_CONFIG` where you put your configuration in json, example:
```json
{
  "protected_headers": ["x-header-one"],
  "routes": [
    {
      "name": "app",
      "path": "/**",
      "url": "http://www.mocky.io/v2/595625d22900008702cd71e8",
      "show_error": true,
      "no_buffer": false
    }
  ]
}
```
2. Your configuration should be loaded
