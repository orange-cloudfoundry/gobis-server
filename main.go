package main

import (
	"github.com/orange-cloudfoundry/gobis-server/cli"
	"os"
	"github.com/orange-cloudfoundry/gobis-server/server"
	"github.com/orange-cloudfoundry/gobis-middlewares"
)

func init() {
	server.AddMiddlewareHandlers(middlewares.DefaultHandlers()...)
}
func main() {
	gobisServer := cli.NewApp()
	gobisServer.Run(os.Args)
}
