package cli

import (
	"github.com/cloudfoundry-community/gautocloud"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-server/server"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"strings"
)

type GobisServerApp struct {
	*cli.App
}

func NewApp() *GobisServerApp {
	app := &GobisServerApp{cli.NewApp()}
	app.Name = "gobis-server"
	app.Version = "1.2.1"
	app.Usage = "Create a gobis server based on a config file"
	app.ErrWriter = os.Stderr
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config-path, c",
			Value: "gobis-config.yml",
			Usage: "Path to the config file",
		},
		cli.StringFlag{
			Name:  "cert",
			Value: "server.crt",
			Usage: "Path to a cert file or a cert content to enable https server",
		},
		cli.StringFlag{
			Name:  "key",
			Value: "server.key",
			Usage: "Path to a key file or a key content to enable https server",
		},
		cli.StringFlag{
			Name:  "log-level, l",
			Value: "info",
			Usage: "Log level to use",
		},
		cli.StringFlag{
			Name:  "forward-url, f",
			Usage: "If set all non-found url by gobis will be forwarded to this url",
		},
		cli.BoolFlag{
			Name:  "log-json, j",
			Usage: "Write log in json",
		},
		cli.BoolFlag{
			Name:  "no-color",
			Usage: "Logger will not display colors",
		},
		cli.StringFlag{
			Name:  "lets-encrypt, le",
			Usage: "If set server will use a certificate generated with let's encypt, value should be your domain(s) (e.g.: --lets-encrypt=example.com[,seconddomain.com]). Host and port will be overwritten to use 0.0.0.0:443",
		},
	}
	app.Action = app.RunServer
	return app
}

func (a *GobisServerApp) Run(arguments []string) (err error) {
	a.Action = a.RunServer
	return a.App.Run(arguments)
}
func (a *GobisServerApp) RunServer(c *cli.Context) error {
	if gautocloud.IsInACloudEnv() {
		gobisServer, err := server.NewGobisCloudServer()
		if err != nil {
			return err
		}
		return gobisServer.Run()
	}
	config := a.loadServerConfig(c)
	a.loadLogConfig(config)

	gobisServer, err := server.NewGobisServer(config)
	if err != nil {
		return err
	}
	return gobisServer.Run()
}
func (a GobisServerApp) loadServerConfig(c *cli.Context) *server.GobisServerConfig {
	config := &server.GobisServerConfig{}
	config.Routes = make([]gobis.ProxyRoute, 0)
	config.NoColor = c.GlobalBool("no-color")
	config.LogJson = c.GlobalBool("log-json")
	config.LogLevel = c.GlobalString("log-level")
	config.Cert = c.GlobalString("cert")
	config.Key = c.GlobalString("key")
	config.ConfigPath = c.GlobalString("config-path")
	config.ForwardUrl = c.GlobalString("forward-url")
	leDomains := c.GlobalString("lets-encrypt")
	if leDomains != "" {
		config.LetsEncryptDomains = strings.Split(leDomains, ",")
	}

	return config
}
func (a GobisServerApp) loadLogConfig(c *server.GobisServerConfig) {
	if c.LogJson {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableColors: c.NoColor,
		})
	}
	if c.LogLevel == "" {
		return
	}
	switch strings.ToUpper(c.LogLevel) {
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
		return
	case "WARN":
		log.SetLevel(log.WarnLevel)
		return
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
		return
	case "PANIC":
		log.SetLevel(log.PanicLevel)
		return
	case "FATAL":
		log.SetLevel(log.FatalLevel)
		return
	}
	return
}
