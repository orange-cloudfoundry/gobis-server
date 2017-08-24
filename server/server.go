package server

import (
	"fmt"
	"github.com/cloudfoundry-community/gautocloud"
	"github.com/cloudfoundry-community/gautocloud/connectors/generic"
	"github.com/orange-cloudfoundry/gobis"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
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
	Host               string             `json:"host" yaml:"host"`
	Port               int                `json:"port" yaml:"port"`
	Routes             []gobis.ProxyRoute `json:"routes" yaml:"routes"`
	StartPath          string             `json:"start_path" yaml:"start_path"`
	ProtectedHeaders   []string           `json:"protected_headers" yaml:"protected_headers"`
	Cert               string             `json:"cert" yaml:"cert" cloud-default:"server.crt"`
	Key                string             `json:"key" yaml:"key" cloud-default:"server.key"`
	LogLevel           string             `json:"log_level" yaml:"log_level" cloud-default:"info"`
	LogJson            bool               `json:"log_json" yaml:"log_json"`
	NoColor            bool               `json:"no_color" yaml:"no_color"`
	ConfigPath         string             `json:"config_path" yaml:"config_path" cloud-default:"gobis-config.yml"`
	ForwardUrl         string             `json:"forward_url" yaml:"forward_url"`
	LetsEncryptDomains []string           `json:"lets_encrypt_domain" yaml:"lets_encrypt_domain"`
}

type GobisServer struct {
	config  *GobisServerConfig
	handler gobis.GobisHandler
}

func NewGobisServer(config *GobisServerConfig) (*GobisServer, error) {
	server := &GobisServer{config: config}
	err := server.Load()
	if err != nil {
		return nil, err
	}
	return server, nil
}
func NewGobisCloudServer() (*GobisServer, error) {
	config := &GobisServerConfig{}
	err := gautocloud.Inject(config)
	if err != nil {
		return nil, err
	}
	log.Info("Loading config from cloud environment")
	return NewGobisServer(config)
}
func (s *GobisServer) Load() error {
	if s.config.Port == 0 {
		port, _ := strconv.Atoi(os.Getenv("PORT"))
		s.config.Port = port
	}
	if gautocloud.IsInACloudEnv() {
		if _, ok := gautocloud.GetAppInfo().Properties["port"]; ok {
			s.config.Port = gautocloud.GetAppInfo().Properties["port"].(int)
		}
	}
	s.mergeFileConfig(s.config)
	if len(s.config.Routes) == 0 {
		return fmt.Errorf("You must configure routes in your config file")
	}
	forwardedUrl, err := url.Parse(s.config.ForwardUrl)
	if err != nil {
		return fmt.Errorf("Cannot parse forward url: " + err.Error())
	}
	s.handler, err = gobis.NewDefaultHandler(
		gobis.DefaultHandlerConfig{
			ProtectedHeaders: s.config.ProtectedHeaders,
			StartPath:        s.config.StartPath,
			Host:             s.config.Host,
			Routes:           s.config.Routes,
			Port:             s.config.Port,
			ForwardedUrl:     forwardedUrl,
		},
		gobis.NewRouterFactory(MiddlewareHandlers()...),
	)
	if err != nil {
		return err
	}
	s.config.Cert, err = s.getTlsFilePath(s.config.Cert)
	if err != nil {
		return err
	}
	s.config.Key, err = s.getTlsFilePath(s.config.Key)
	if err != nil {
		return err
	}
	return nil
}
func (s GobisServer) Run() error {
	servAddr := s.handler.GetServerAddr()
	if s.config.LetsEncryptDomains != nil && len(s.config.LetsEncryptDomains) > 0 {
		log.Info("Serving gobis server in https on ':443' with let's encrypt certificate (443 is mandatory by let's encrypt).")
		return http.Serve(autocert.NewListener(s.config.LetsEncryptDomains...), s.handler)
	}
	log.Infof("Serving gobis server in https on address '%s'", servAddr)
	err := http.ListenAndServeTLS(servAddr, s.config.Cert, s.config.Key, s.handler)
	if err != nil {
		log.Warn("Server wasn't start with tls, maybe you didn't set a cert and key file.")
		log.Warn("For security reasons you should use tls.")
		log.Warn("You can use tls easily by setting lets encrypt over cli with --lets-encrypt=example.com,example2.com or through config with key 'lets_encrypt_domain'")
		log.Warnf("Errors given: '%s'", err.Error())
	}
	log.Infof("Serving an insecure gobis server in http on address '%s'", servAddr)
	return http.ListenAndServe(servAddr, s.handler)
}
func (s GobisServer) getTlsFilePath(tlsConf string) (string, error) {
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
func (s GobisServer) mergeFileConfig(c *GobisServerConfig) {
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
