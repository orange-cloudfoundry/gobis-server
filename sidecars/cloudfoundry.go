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
	"path/filepath"
)

const (
	routeFile   string = "route.yml"
	gobisFolder string = ".gobis"
)

type CFSidecar struct {
}

func (s CFSidecar) Setup(config *server.GobisServerConfig, appPort int) error {
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
	route.Path = gobis.NewPathMatcher("/**")
	route.Url = fmt.Sprintf("http://127.0.0.1:%d", appPort)
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
	config.Routes = []gobis.ProxyRoute{route}
	log.Infof("Real app is listening on port '%s' , you can use internal domain to bypass gobis", appPort)
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

func (CFSidecar) CloudEnvName() string {
	return cloudenv.CfCloudEnv{}.Name()
}
