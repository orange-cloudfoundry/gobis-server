package sidecars

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

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


func mergeMap(old, new map[string]interface{}) map[string]interface{} {
	for k, v := range new {
		old[k] = v
	}
	return old
}

func mapInterfaceToString(m map[interface{}]interface{}) map[string]interface{} {
	n := make(map[string]interface{})
	for k, v := range m {
		n[fmt.Sprint(k)] = v
	}
	return n
}
