package main

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
)

func requireSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusForbidden, "session required")
	}
}

func protectedFile(c echo.Context) error {
	return c.String(http.StatusOK, "protected")
}

func main() {
	e := echo.New()
	admin := e.Group("/admin", requireSession)
	admin.GET("/*", protectedFile)
	e.StaticFS("/", os.DirFS("public"))
	if err := e.Start(":8080"); err != nil {
		e.Logger.Fatal(err)
	}
}
