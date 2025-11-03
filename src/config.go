package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"sleuth/internal/log"

	"github.com/usvc/go-config"
	"gopkg.in/yaml.v3"
)

type ConfigLocalAddressTarget struct {
	Address string `yaml:"address"`
	Type    string `yaml:"type"`
}

type ConfigLocalAddress struct {
	Name   string                     `yaml:"name"`
	Target []ConfigLocalAddressTarget `yaml:"target"`
}

type Config struct {
	ListenAddr          string               `yaml:"listen"`
	UpstreamDNS         []string             `yaml:"upstream"`
	BlacklistSources    []string             `yaml:"blacklist"`
	BlacklistRenewal    int                  `yaml:"blacklistRenewal"`
	BlacklistEverything bool                 `yaml:"blacklistEverything"`
	Whitelist           []string             `yaml:"whitelist"`
	LocalAddresses      []ConfigLocalAddress `yaml:"local"`
}

var ConfigInstance *Config = &Config{}

func GetConfig() *Config {
	return ConfigInstance
}

func (c *Config) ReadConfig() {
	configPath, err := os.Getwd()
	if (err != nil) || (configPath == "") {
		log.Error("could neither get system config dir nor current working dir")
		os.Exit(1)
	}
	configPath = filepath.Join(configPath, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Error("could not read config yaml from %s\n", configPath)
		os.Exit(1)
	}
	c.ReadConfigData(data)
	c.ReadEnv()
}

func (c *Config) ReadConfigData(data []byte) {
	if err := yaml.Unmarshal(data, &c); err != nil {
		log.Error("could not parse config yaml: %s\n", err.Error())
		os.Exit(1)
	}
}

func (c *Config) ReadEnv() {
	listenAddr := c.getEnv("LISTEN_ADDR", "")
	if listenAddr != "" {
		c.ListenAddr = listenAddr
	}
	for i := 1; i <= 10; i++ {
		server := c.getEnv("UPSTREAM_DNS_"+strconv.Itoa(i), "")
		if server != "" {
			c.UpstreamDNS = append(c.UpstreamDNS, server)
		}
	}
}

func (c *Config) Print() {
	s, _ := yaml.Marshal(c)
	log.Info("Using config:\n" + string(s))
}

func (c *Config) getEnv(key, defaultValue string) string {
	res := os.Getenv(key)
	if res == "" {
		return defaultValue
	}
	return res
}

// cloudshell config
var conf = config.Map{
	"allowed-hostnames": &config.StringSlice{
		Default:   []string{"localhost"},
		Usage:     "comma-delimited list of hostnames that are allowed to connect to the websocket",
		Shorthand: "H",
	},
	"arguments": &config.StringSlice{
		Default:   []string{},
		Usage:     "comma-delimited list of arguments that should be passed to the terminal command",
		Shorthand: "r",
	},
	"command": &config.String{
		Default:   "/bin/bash",
		Usage:     "absolute path to command to run",
		Shorthand: "t",
	},
	"connection-error-limit": &config.Int{
		Default:   10,
		Usage:     "number of times a connection should be re-attempted before it's considered dead",
		Shorthand: "l",
	},
	"keepalive-ping-timeout": &config.Int{
		Default:   20,
		Usage:     "maximum duration in seconds between a ping message and its response to tolerate",
		Shorthand: "k",
	},
	"max-buffer-size-bytes": &config.Int{
		Default:   512,
		Usage:     "maximum length of input from terminal",
		Shorthand: "B",
	},
	"log-format": &config.String{
		Default: "text",
		Usage:   fmt.Sprintf("defines the format of the logs - one of ['%s']", strings.Join(log.ValidFormatStrings, "', '")),
	},
	"log-level": &config.String{
		Default: "debug",
		Usage:   fmt.Sprintf("defines the minimum level of logs to show - one of ['%s']", strings.Join(log.ValidLevelStrings, "', '")),
	},
	"path-liveness": &config.String{
		Default: "/healthz",
		Usage:   "url path to the liveness probe endpoint",
	},
	"path-metrics": &config.String{
		Default: "/metrics",
		Usage:   "url path to the prometheus metrics endpoint",
	},
	"path-readiness": &config.String{
		Default: "/readyz",
		Usage:   "url path to the readiness probe endpoint",
	},
	"path-xtermjs": &config.String{
		Default: "/xterm.js",
		Usage:   "url path to the endpoint that xterm.js should attach to",
	},
	"server-addr": &config.String{
		Default:   "0.0.0.0",
		Usage:     "ip interface the server should listen on",
		Shorthand: "a",
	},
	"server-port": &config.Int{
		Default:   8376,
		Usage:     "port the server should listen on",
		Shorthand: "p",
	},
	"workdir": &config.String{
		Default:   ".",
		Usage:     "working directory",
		Shorthand: "w",
	},
}
