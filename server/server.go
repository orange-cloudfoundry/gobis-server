package server

import (
	"crypto/tls"
	"fmt"
	"github.com/cloudfoundry-community/gautocloud"
	"github.com/orange-cloudfoundry/gobis"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

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
	ConfigPath         string             `json:"config_path" yaml:"config_path" cloud-default:"config.yml"`
	ForwardUrl         string             `json:"forward_url" yaml:"forward_url"`
	LetsEncryptDomains []string           `json:"lets_encrypt_domains" yaml:"lets_encrypt_domains"`
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

func (s *GobisServer) Load() error {
	s.loadLogConfig()
	if s.config.Port == 0 {
		port, _ := strconv.Atoi(os.Getenv("PORT"))
		s.config.Port = port
	}
	if gautocloud.IsInACloudEnv() {
		if _, ok := gautocloud.GetAppInfo().Properties["port"]; ok {
			s.config.Port = gautocloud.GetAppInfo().Properties["port"].(int)
		}
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
func (s GobisServer) checkCert(cert, key string) error {
	_, err := tls.LoadX509KeyPair(cert, key)
	return err
}
func (s GobisServer) Run() error {
	servAddr := s.handler.GetServerAddr()
	if s.config.LetsEncryptDomains != nil && len(s.config.LetsEncryptDomains) > 0 {
		log.Info("Serving gobis server in https on ':443' with let's encrypt certificate (443 is mandatory by let's encrypt).")
		return http.Serve(autocert.NewListener(s.config.LetsEncryptDomains...), s.handler)
	}
	log.Infof("Serving gobis server in https on address '%s'", servAddr)
	err := s.checkCert(s.config.Cert, s.config.Key)
	if err == nil {
		return http.ListenAndServeTLS(servAddr, s.config.Cert, s.config.Key, s.handler)
	}
	log.Warn("Server wasn't start with tls, maybe you didn't set a cert and key file.")
	log.Warn("For security reasons you should use tls.")
	log.Warn("You can use tls easily by setting lets encrypt over cli with --lets-encrypt=example.com,example2.com or through config with key 'lets_encrypt_domain'")
	log.Warnf("Errors given: '%s'", err.Error())

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
func (s GobisServer) loadLogConfig() {
	c := s.config

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
