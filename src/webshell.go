package main

import (
	"net/http"
	"sleuth/pkg/xtermjs"
	"time"

	"github.com/gin-gonic/gin"
)

type webShell struct {
}

func webShellInit(p *Portal) *webShell {
	u := &webShell{}

	command := conf.GetString("command")
	connectionErrorLimit := conf.GetInt("connection-error-limit")
	arguments := conf.GetStringSlice("arguments")
	allowedHostnames := conf.GetStringSlice("allowed-hostnames")
	keepalivePingTimeout := time.Duration(conf.GetInt("keepalive-ping-timeout")) * time.Second
	maxBufferSizeBytes := conf.GetInt("max-buffer-size-bytes")

	xtermjsHandlerOptions := xtermjs.HandlerOpts{
		AllowedHostnames:     allowedHostnames,
		Arguments:            arguments,
		Command:              command,
		ConnectionErrorLimit: connectionErrorLimit,
		CreateLogger: func(connectionUUID string, r *http.Request) xtermjs.Logger {
			createRequestLog(r, map[string]interface{}{"connection_uuid": connectionUUID}).Infof("created logger for connection '%s'", connectionUUID)
			return createRequestLog(nil, map[string]interface{}{"connection_uuid": connectionUUID})
		},
		KeepalivePingTimeout: keepalivePingTimeout,
		MaxBufferSizeBytes:   maxBufferSizeBytes,
	}

	p.router.GET("/shell", p.serveTemplate)
	p.router.Any("/shell/xterm", xtermjs.GetHandler(xtermjsHandlerOptions))

	// readiness probe endpoint
	p.router.GET("shell/ready", func(c *gin.Context) {
		c.Writer.WriteHeader(http.StatusOK)
		c.Writer.Write([]byte("ok"))
	})

	// liveness probe endpoint
	p.router.GET("shell/health", func(c *gin.Context) {
		c.Writer.WriteHeader(http.StatusOK)
		c.Writer.Write([]byte("ok"))
	})

	// metrics endpoint
	//router.Handle(pathMetrics, promhttp.Handler())

	// version endpoint
	/*router.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(VersionInfo))
	})*/

	// this is the endpoint for serving xterm.js assets
	//depenenciesDirectory := path.Join(".", "./node_modules")
	//p.router.PathPrefix("/assets").Handler(http.StripPrefix("/assets", http.FileServer(http.Dir(depenenciesDirectory))))
	p.router.Static("/assets", "./node_modules")

	// this is the endpoint for the root path aka website
	//publicAssetsDirectory := path.Join(workingDirectory, "./public")
	//router.PathPrefix("/").Handler(http.FileServer(http.Dir(publicAssetsDirectory)))

	// start memory logging pulse
	logWithMemory := createMemoryLog()
	go func(tick *time.Ticker) {
		for {
			logWithMemory.Debug("tick")
			<-tick.C
		}
	}(time.NewTicker(time.Second * 30))

	return u
}
