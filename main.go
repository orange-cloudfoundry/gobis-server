package main

import (
	"github.com/urfave/cli"
	"os"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	log "github.com/sirupsen/logrus"
	"net/http"
	"fmt"
	"strings"
	"strconv"
	"github.com/orange-cloudfoundry/gobis-middlewares"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/cloudfoundry-community/gautocloud"
	"github.com/cloudfoundry-community/gautocloud/connectors/generic"
	"net/url"
)

func init() {
	gautocloud.RegisterConnector(generic.NewSchemaBasedGenericConnector(
		"gobis-config",
		".*gobis(_|-)config",
		[]string{".*gobis(_|-)config"},
		GobisServerConfig{},
	))
}

type GobisServerConfig struct {
	Host             string `json:"host" yaml:"host"`
	Port             int `json:"port" yaml:"port"`
	Routes           []gobis.ProxyRoute `json:"routes" yaml:"routes"`
	StartPath        string `json:"start_path" yaml:"start_path"`
	ProtectedHeaders []string `json:"protected_headers" yaml:"protected_headers"`
	Cert             string
	Key              string
	LogLevel         string
	LogJson          bool
	NoColor          bool
	ConfigPath       string
	ForwardUrl       string
}

func main() {
	app := cli.NewApp()
	app.Name = "gobis-server"
	app.Version = "1.1.1"
	app.Usage = "Create a gobis server based on a config file"
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
	}
	app.Action = runServer
	app.Run(os.Args)
}
func loadServerConfig(c *cli.Context) GobisServerConfig {
	var config GobisServerConfig
	err := gautocloud.Inject(&config)
	if err == nil {
		log.Info("Loading config from cloud environment")
		return config
	}
	config.Routes = make([]gobis.ProxyRoute, 0)
	config.NoColor = c.GlobalBool("no-color")
	config.LogJson = c.GlobalBool("log-json")
	config.LogLevel = c.GlobalString("log-level")
	config.Cert = c.GlobalString("cert")
	config.Key = c.GlobalString("key")
	config.ConfigPath = c.GlobalString("config-path")
	config.ForwardUrl = c.GlobalString("forward-url")
	return config
}
func loadLogConfig(c GobisServerConfig) {
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
func runServer(c *cli.Context) error {
	config := loadServerConfig(c)
	loadLogConfig(config)
	if config.Port == 0 {
		port, _ := strconv.Atoi(os.Getenv("PORT"))
		config.Port = port
	}
	if gautocloud.IsInACloudEnv() {
		if _, ok := gautocloud.GetAppInfo().Properties["port"]; ok {
			config.Port = gautocloud.GetAppInfo().Properties["port"].(int)
		}
	}
	mergeFileGobisConfig(&config)
	if len(config.Routes) == 0 {
		return fmt.Errorf("You must configure routes in your config file")
	}
	forwardedUrl, err := url.Parse(config.ForwardUrl)
	if err != nil {
		return fmt.Errorf("Cannot parse forward url: " + err.Error())
	}
	gobisHandler, err := gobis.NewDefaultHandler(
		gobis.DefaultHandlerConfig{
			ProtectedHeaders: config.ProtectedHeaders,
			StartPath: config.StartPath,
			Host: config.Host,
			Routes: config.Routes,
			Port: config.Port,
			ForwardedUrl: forwardedUrl,
		},
		gobis.NewRouterFactory(middlewares.DefaultHandlers()...),
	)
	if err != nil {
		return err
	}
	servAddr := gobisHandler.GetServerAddr()
	certPath, err := getTlsFilePath(config.Cert)
	if err != nil {
		return err
	}
	keyPath, err := getTlsFilePath(config.Key)
	if err != nil {
		return err
	}
	log.Infof("Serving gobis server in https on address '%s'", servAddr)
	err = http.ListenAndServeTLS(servAddr, certPath, keyPath, gobisHandler)
	if err != nil {
		log.Warn("Server wasn't start with tls, maybe you didn't set a cert and key file.")
		log.Warn("For security reasons you should use tls.")
		log.Warnf("Errors given: %s", err.Error())
	}
	log.Infof("Serving an insecure gobis server in http on address '%s'", servAddr)
	return http.ListenAndServe(servAddr, gobisHandler)
}
func getTlsFilePath(tlsConf string) (string, error) {
	if tlsConf == "" {
		return "", nil
	}
	_, err := os.Stat(tlsConf)
	if err == nil {
		return tlsConf, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	f, err := ioutil.TempFile("", "gobis")
	if err != nil {
		return "", err
	}
	defer f.Close()
	f.WriteString(tlsConf)
	return f.Name(), nil
}
func mergeFileGobisConfig(c *GobisServerConfig) {
	dat, err := ioutil.ReadFile(c.ConfigPath)
	if err != nil {
		return
	}
	confFile := gobis.DefaultHandlerConfig{}
	err = yaml.Unmarshal(dat, &confFile)
	if err != nil {
		log.Warnf("Could not unmarshal config file found: %s", err.Error())
		return
	}
	if confFile.Port != 0 && !gautocloud.IsInACloudEnv() {
		c.Port = confFile.Port
	}
	if confFile.Host != "" {
		c.Host = confFile.Host
	}
	if confFile.StartPath != "" {
		c.StartPath = confFile.StartPath
	}
	c.ProtectedHeaders = append(c.ProtectedHeaders, confFile.ProtectedHeaders...)
	c.Routes = append(c.Routes, confFile.Routes...)
	return
}