package main

import (
	"github.com/orange-cloudfoundry/gobis-middlewares"
	"github.com/orange-cloudfoundry/gobis-server/cli"
	"github.com/orange-cloudfoundry/gobis-server/server"
	log "github.com/sirupsen/logrus"
	"os"
)

var Version string

func init() {
	server.AddMiddlewareHandlers(middlewares.DefaultHandlers()...)
}
func main() {
	gobisServer := cli.NewApp(Version)
	err := gobisServer.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}
