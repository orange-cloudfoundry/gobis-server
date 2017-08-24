package main

import (
	"github.com/orange-cloudfoundry/gobis-middlewares"
	"github.com/orange-cloudfoundry/gobis-server/cli"
	"github.com/orange-cloudfoundry/gobis-server/server"
	"os"
)

func init() {
	server.AddMiddlewareHandlers(middlewares.DefaultHandlers()...)
}
func main() {
	gobisServer := cli.NewApp()
	gobisServer.Run(os.Args)
}
