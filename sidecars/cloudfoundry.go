package sidecars

import (
	"fmt"
	"github.com/cloudfoundry-community/gautocloud"
	"github.com/cloudfoundry-community/gautocloud/cloudenv"
	"github.com/hashicorp/go-multierror"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-server/server"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	launcherName string = "launcher"
	routeFile    string = "route.yml"
	procFile     string = "Procfile"
	gobisFolder  string = ".gobis"
)

type CFSidecar struct {
}

func (s CFSidecar) Run(config *server.GobisServerConfig) error {
	entry := log.WithField("sidecar", s.CloudEnvName())

	appInfo := gautocloud.GetAppInfo()
	config.Cert = ""
	config.Host = ""
	config.LetsEncryptDomains = []string{}
	config.Port = appInfo.Port

	entry.Debug("Loading route config...")
	route, err := s.loadingRouteConfig()
	if err != nil {
		entry.Warnf(
			"Something went wrong when loading %s, so it use only default configuration, see details: %s",
			filepath.Join(gobisFolder, routeFile),
			err.Error(),
		)
	}
	route.Name = "proxy-" + appInfo.Name
	route.Path = "/**"
	appPort := generatePort(8081, 65534)
	route.Url = fmt.Sprintf("http://127.0.0.1:%d", appPort)
	config.Routes = []gobis.ProxyRoute{route}
	entry.Debug("Finished loading route ...")

	entry.Debug("Loading params files...")
	params, err := s.loadingRouteParams()
	if err != nil {
		entry.Warnf(
			"Something went wrong when loading params files: %s",
			err.Error(),
		)
	}
	if route.MiddlewareParams != nil {
		params = mergeMap(params, route.MiddlewareParams.(map[string]interface{}))
	}
	route.MiddlewareParams = params
	entry.Debug("Finished loading params files...")

	entry.Debug("Executing launcher to start real process ...")
	lPath := s.launcherPath()
	wd, _ := os.Getwd()
	cmd := exec.Command(lPath, wd, s.getUserStartCommand(), "")
	cmd.Env = s.appEnv(appPort)
	lEntryOut := entry.WithField("process", lPath)
	lEntryOut.Level = log.InfoLevel
	lEntryErr := entry.WithField("process", lPath)
	lEntryErr.Level = log.ErrorLevel

	cmd.Stdout = lEntryOut.Writer()
	cmd.Stderr = lEntryErr.Writer()
	err = cmd.Run()
	if err != nil {
		return err
	}
	entry.Debug("Finished executing launcher to start real process.")

	log.Infof("Real app is listening on port '%d' , you can use internal domain to bypass gobis", appPort)
	return nil
}

func (CFSidecar) loadingRouteConfig() (gobis.ProxyRoute, error) {
	var route gobis.ProxyRoute
	b, err := ioutil.ReadFile(filepath.Join(gobisFolder, routeFile))
	if err != nil {
		return route, err
	}
	if err == nil {
		err = yaml.Unmarshal(b, route)
		if err != nil {
			return route, err
		}
	}
	return route, nil
}

func (CFSidecar) loadingRouteParams() (map[string]interface{}, error) {
	params := make(map[string]interface{})
	var files []string
	var err error
	files, err = filepath.Glob(filepath.Join(gobisFolder, "*-params.yml"))
	if err != nil {
		return params, err
	}
	var result error
	for _, f := range files {
		b, err := ioutil.ReadFile(f)
		if err != nil {
			result = multierror.Append(result, err)
			continue
		}
		var newParams map[string]interface{}
		err = yaml.Unmarshal(b, &newParams)
		if err != nil {
			result = multierror.Append(result, err)
			continue
		}
		params = mergeMap(params, newParams)
	}
	return params, result
}

func (CFSidecar) appEnv(port int) []string {
	envv := os.Environ()
	hasPort := false
	for i := 0; i < len(envv); i++ {
		if strings.HasPrefix(envv[i], "VCAP_APP_PORT=") {
			envv[i] = fmt.Sprintf("VCAP_APP_PORT=%d", port)
		}
		if strings.HasPrefix(envv[i], "PORT=") {
			envv[i] = fmt.Sprintf("PORT=%d", port)
			hasPort = true
		}
	}
	if !hasPort {
		envv = append(envv, fmt.Sprintf("PORT=%d", port))
	}
	return envv
}

func (CFSidecar) getUserStartCommand() string {
	b, err := ioutil.ReadFile(procFile)
	if err != nil {
		return ""
	}
	startCommandS := struct {
		StartCommand string `yaml:"start"`
	}{}
	err = yaml.Unmarshal(b, &startCommandS)
	if err != nil {
		return ""
	}
	return startCommandS.StartCommand
}

func (CFSidecar) launcherPath() string {
	lName := launcherName
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = "C:\\tmp"
		lName += ".exe"
	}
	path := filepath.Join(base, "lifecycle", lName)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		wd, _ := os.Getwd()
		return filepath.Join(wd, lName)
	}

	return path
}

func (CFSidecar) CloudEnvName() string {
	return cloudenv.CfCloudEnv{}.Name()
}
