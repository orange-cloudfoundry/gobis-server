package cli

import (
	"fmt"
	"github.com/cloudfoundry-community/gautocloud"
	"github.com/cloudfoundry-community/gautocloud/cloudenv"
	"github.com/cloudfoundry-community/gautocloud/connectors/generic"
	"github.com/cloudfoundry-community/gautocloud/interceptor/cli/urfave"
	"github.com/cloudfoundry-community/gautocloud/interceptor/configfile"
	"github.com/cloudfoundry-community/gautocloud/loader"
	"github.com/orange-cloudfoundry/gobis-server/server"
	"github.com/orange-cloudfoundry/gobis-server/sidecars"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"strings"
)

var cliInterceptor *urfave.CliInterceptor
var confFileIntercept *configfile.ConfigFileInterceptor

func init() {
	confFileIntercept = configfile.NewConfigFile()
	cliInterceptor = urfave.NewCli()
	gautocloud.RegisterConnector(generic.NewConfigGenericConnector(
		server.GobisServerConfig{},
		confFileIntercept,
		cliInterceptor,
	))
}

type GobisServerApp struct {
	*cli.App
}

func NewApp() *GobisServerApp {
	app := &GobisServerApp{cli.NewApp()}
	app.Name = "gobis-server"
	app.Version = "1.5.2"
	app.Usage = "Create a gobis server based on a config file"
	app.ErrWriter = os.Stderr
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config-path, c",
			Value:  cloudenv.DEFAULT_CONFIG_PATH,
			Usage:  "Path to the config file (This file will not be used in a cloud env like Cloud Foundry, Heroku or kubernetes)",
			EnvVar: cloudenv.LOCAL_CONFIG_ENV_KEY,
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
			Usage: "Log level to use",
		},
		cli.BoolFlag{
			Name:  "log-json, j",
			Usage: "Write log in json",
		},
		cli.BoolFlag{
			Name:  "sidecar, s",
			Usage: "Run server as a sidecar, you can use sidecar-env to force sidecar env detection",
		},
		cli.StringFlag{
			Name:  "sidecar-env",
			Usage: "Must be use with --sidecar, this permit to force sidecar env detection",
		},
		cli.BoolFlag{
			Name:  "no-color",
			Usage: "Logger will not display colors",
		},
		cli.StringFlag{
			Name:  "lets-encrypt-domains, led",
			Usage: "If set server will use a certificate generated with let's encrypt, value should be your domain(s) (e.g.: --lets-encrypt=example.com[,seconddomain.com]). Host and port will be overwritten to use 0.0.0.0:443",
		},
	}
	return app
}

func (a *GobisServerApp) Run(arguments []string) (err error) {
	a.Action = a.RunServer
	return a.App.Run(arguments)
}

func (a *GobisServerApp) loadSidecar(config *server.GobisServerConfig, sidecarEnv string) error {
	if sidecarEnv == "" {
		sidecarEnv = gautocloud.CurrentCloudEnv().Name()
	}
	log.Info("Loading sidecar ...")
	for _, sidecar := range sidecars.Retrieve() {
		if sidecar.CloudEnvName() == sidecarEnv {
			log.Infof("Sidecar for %s is loading", sidecar.CloudEnvName())
			return sidecar.Run(config)
		}
	}
	log.Warnf("No sidecar has been found for %s environment", sidecarEnv)
	return nil
}

func (a *GobisServerApp) RunServer(c *cli.Context) error {
	cliInterceptor.SetContext(c)
	confPath := c.GlobalString("config-path")
	confFileIntercept.SetConfigPath(confPath)

	config := &server.GobisServerConfig{}
	err := gautocloud.Inject(config)
	if err != nil {
		if c.GlobalBool("sidecar") {
			config.Cert = c.GlobalString("cert")
			config.Key = c.GlobalString("key")
			config.LogLevel = c.GlobalString("log-level")
			config.LogJson = c.GlobalBool("log-json")
			config.NoColor = c.GlobalBool("no-color")
			if c.GlobalString("lets-encrypt-domains") != "" {
				config.LetsEncryptDomains = strings.Split(c.GlobalString("lets-encrypt-domains"), ",")
			}
		} else {
			if _, ok := err.(loader.ErrGiveService); ok {
				return fmt.Errorf("configuration cannot be found")
			}
			return err
		}
	}
	loadLogConfig(config)
	if c.GlobalBool("sidecar") {
		err = a.loadSidecar(config, c.GlobalString("sidecar-env"))
		if err != nil {
			return err
		}
	}

	gobisServer, err := server.NewGobisServer(config)
	if err != nil {
		return err
	}

	return gobisServer.Run()
}

func loadLogConfig(c *server.GobisServerConfig) {
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
}
