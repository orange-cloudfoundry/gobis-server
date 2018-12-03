package sidecars

import (
	"github.com/orange-cloudfoundry/gobis-server/server"
	"net"
	"os"
	"strconv"
)

type Sidecar interface {
	Run(*server.GobisServerConfig) error
	CloudEnvName() string
}

func generatePort(minport int, maxport int) int {
	port := minport
	for port <= maxport {

		if isPortAvailable(port) {
			return port
		}
		port++
	}
	return 8081
}

func isPortAvailable(num int) bool {
	var appPort int
	envPort := os.Getenv("PORT")
	_, err := strconv.Atoi(envPort)
	if err == nil {
		appPort, _ = strconv.Atoi(envPort)
	}
	if appPort == num {
		return false
	}
	l, err := net.Listen("tcp", ":"+strconv.Itoa(num))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func Retrieve() []Sidecar {
	return []Sidecar{
		CFSidecar{},
	}
}

func mergeMap(old, new map[string]interface{}) map[string]interface{} {
	for k, v := range new {
		old[k] = v
	}
	return old
}
