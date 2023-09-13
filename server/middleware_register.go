package server

import (
	"github.com/orange-cloudfoundry/gobis"
)

var middlewareHandlers = make([]gobis.MiddlewareHandler, 0)

func ClearMiddlewareHandlers() {
	middlewareHandlers = make([]gobis.MiddlewareHandler, 0)
}

func MiddlewareHandlers() []gobis.MiddlewareHandler {
	return middlewareHandlers
}
func AddMiddlewareHandlers(handlers ...gobis.MiddlewareHandler) {
	middlewareHandlers = append(middlewareHandlers, handlers...)
}
