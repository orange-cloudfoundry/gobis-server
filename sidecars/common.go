package sidecars

import (
	"fmt"
)

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
