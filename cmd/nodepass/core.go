package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/NodePassProject/logs"
	"github.com/NodePassProject/nodepass/internal"
)

type commandLine struct {
	args       []string
	password   *string
	tunnelAddr *string
	tunnelPort *string
	targetAddr *string
	targetPort *string
	targets    *string
	log        *string
	tls        *string
	crt        *string
	key        *string
	dns        *string
	sni        *string
	lbs        *string
	min        *string
	max        *string
	mode       *string
	pool       *string
	dial       *string
	read       *string
	rate       *string
	slot       *string
	proxy      *string
	block      *string
	notcp      *string
	noudp      *string
}

func run() {
	if err := start(os.Args); err != nil {
		exit(err)
	}
}

func start(args []string) error {
	parsedURL, err := newCommandLine(args).parse()
	if err != nil {
		return fmt.Errorf("start: parse command failed: %w", err)
	}

	logger := initLogger(parsedURL.Query().Get("log"))

	core, err := createCore(parsedURL, logger)
	if err != nil {
		return fmt.Errorf("start: create core failed: %w", err)
	}

	core.Run()
	return nil
}

func exit(err error) {
	errMsg := "none"
	if err != nil {
		errMsg = err.Error()
	}
	fmt.Fprintf(os.Stderr,
		"nodepass-%s %s/%s pid=%d error=%s\n\nrun 'nodepass --help' for usage\n",
		version, runtime.GOOS, runtime.GOARCH, os.Getpid(), errMsg)

	os.Exit(1)
}

func initLogger(level string) *logs.Logger {
	logger := logs.NewLogger(logs.Info, true)
	switch level {
	case "none":
		logger.SetLogLevel(logs.None)
	case "debug":
		logger.SetLogLevel(logs.Debug)
		logger.Debug("Init log level: DEBUG")
	case "warn":
		logger.SetLogLevel(logs.Warn)
		logger.Warn("Init log level: WARN")
	case "error":
		logger.SetLogLevel(logs.Error)
		logger.Error("Init log level: ERROR")
	case "event":
		logger.SetLogLevel(logs.Event)
		logger.Event("Init log level: EVENT")
	default:
	}
	return logger
}

func createCore(parsedURL *url.URL, logger *logs.Logger) (interface{ Run() }, error) {
	tlsCode, tlsConfig := getTLSProtocol(parsedURL, logger)
	switch parsedURL.Scheme {
	case "server":
		return internal.NewServer(parsedURL, tlsCode, tlsConfig, logger)
	case "client":
		return internal.NewClient(parsedURL, logger)
	case "master":
		return internal.NewMaster(parsedURL, tlsCode, tlsConfig, logger, version)
	default:
		return nil, fmt.Errorf("createCore: unknown core: %v", parsedURL)
	}
}

func getTLSProtocol(parsedURL *url.URL, logger *logs.Logger) (string, *tls.Config) {
	tlsConfig, err := internal.NewTLSConfig()
	if err != nil {
		logger.Error("Generate TLS config failed: %v", err)
		logger.Warn("TLS code-0: nil cert")
		return "0", nil
	}

	tlsConfig.MinVersion = tls.VersionTLS13

	switch parsedURL.Query().Get("tls") {
	case "1":
		logger.Info("TLS code-1: RAM cert with TLS 1.3")
		return "1", tlsConfig
	case "2":
		crtFile := parsedURL.Query().Get("crt")
		keyFile := parsedURL.Query().Get("key")
		cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
		if err != nil {
			logger.Error("Certificate load failed: %v", err)
			logger.Warn("TLS code-1: RAM cert with TLS 1.3")
			return "1", tlsConfig
		}

		cachedCert := cert
		lastReload := time.Now()
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if time.Since(lastReload) >= internal.ReloadInterval {
					newCert, err := tls.LoadX509KeyPair(crtFile, keyFile)
					if err != nil {
						logger.Error("Certificate reload failed: %v", err)
					} else {
						logger.Debug("TLS cert reloaded: %v", crtFile)
						cachedCert = newCert
					}
					lastReload = time.Now()
				}
				return &cachedCert, nil
			},
		}

		if cert.Leaf != nil {
			logger.Info("TLS code-2: %v with TLS 1.3", cert.Leaf.Subject.CommonName)
		} else {
			logger.Warn("TLS code-2: unknown cert name with TLS 1.3")
		}
		return "2", tlsConfig
	default:
		logger.Warn("TLS code-0: unencrypted")
		return "0", nil
	}
}

func newCommandLine(args []string) *commandLine {
	cmd := &commandLine{
		args: args,
	}

	return cmd
}

func (c *commandLine) parse() (*url.URL, error) {
	if len(c.args) == 2 && strings.Contains(c.args[1], "://") {
		return url.Parse(c.args[1])
	}

	if len(c.args) < 2 {
		return nil, fmt.Errorf("usage: nodepass <command> [options] or nodepass <url>")
	}

	command := c.args[1]
	cmdArgs := c.args[2:]

	switch command {
	case "server":
		return c.parseServerCommand(cmdArgs)
	case "client":
		return c.parseClientCommand(cmdArgs)
	case "master":
		return c.parseMasterCommand(cmdArgs)
	case "help", "-h", "--help":
		c.printHelp()
		os.Exit(0)
	case "version", "-v", "--version":
		fmt.Printf("nodepass-%s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	default:
		fullArg := strings.Join(c.args[1:], " ")
		if strings.Contains(fullArg, "://") {
			return url.Parse(fullArg)
		}
		return nil, fmt.Errorf("unknown command: %s", command)
	}

	return nil, nil
}

func (c *commandLine) addServerFlags(fs *flag.FlagSet) {
	c.password = fs.String("password", "", "Connection password for client authentication")
	c.tunnelAddr = fs.String("tunnel-addr", "", "Server tunnel listening address (e.g., 0.0.0.0)")
	c.tunnelPort = fs.String("tunnel-port", "", "Server tunnel listening port number")
	c.targetAddr = fs.String("target-addr", "", "Backend target address for single target")
	c.targetPort = fs.String("target-port", "", "Backend target port for single target")
	c.targets = fs.String("targets", "", "Multiple targets in comma-separated format (overrides single target)")
	c.log = fs.String("log", "", "Log level: none, debug, warn, error, event")
	c.tls = fs.String("tls", "", "TLS mode: 0=none, 1=self-signed RAM cert, 2=file-based cert")
	c.crt = fs.String("crt", "", "Certificate file path (for tls=2, X509 PEM format)")
	c.key = fs.String("key", "", "Private key file path (for tls=2, PEM format)")
	c.dns = fs.String("dns", "", "DNS cache TTL in seconds (0=disabled)")
	c.lbs = fs.String("lbs", "", "Load balancing strategy: rr (round-robin), random (default: rr)")
	c.max = fs.String("max", "", "Maximum pool capacity for incoming client connections")
	c.mode = fs.String("mode", "", "Run mode: 0=auto (try single then tunnel), 1=single-connection, 2=tunnel pool")
	c.pool = fs.String("pool", "", "Connection pool type, 0=TCP, 1=QUIC, 2=WebSocket, 3=HTTP/2")
	c.dial = fs.String("dial", "", "Outbound source IP for dialing backends (bind to specific interface)")
	c.read = fs.String("read", "", "Read timeout in seconds for idle connections (0=disabled)")
	c.rate = fs.String("rate", "", "Bandwidth rate limit in Mbps (per-connection, 0=unlimited)")
	c.slot = fs.String("slot", "", "Maximum concurrent connection slots (0=unlimited)")
	c.proxy = fs.String("proxy", "", "Enable PROXY protocol v1 support (true/false)")
	c.block = fs.String("block", "", "Block protocols: tcp, udp, or both")
	c.notcp = fs.String("notcp", "", "Disable TCP protocol support (true/false)")
	c.noudp = fs.String("noudp", "", "Disable UDP protocol support (true/false)")
}

func (c *commandLine) addClientFlags(fs *flag.FlagSet) {
	c.password = fs.String("password", "", "Connection password (must match server)")
	c.tunnelAddr = fs.String("tunnel-addr", "", "Server tunnel address (hostname or IP)")
	c.tunnelPort = fs.String("tunnel-port", "", "Server tunnel port number")
	c.targetAddr = fs.String("target-addr", "", "Local target address for forwarding")
	c.targetPort = fs.String("target-port", "", "Local target port for single target")
	c.targets = fs.String("targets", "", "Multiple local targets in comma-separated format")
	c.log = fs.String("log", "", "Log level: none, debug, warn, error, event")
	c.dns = fs.String("dns", "", "DNS cache TTL in seconds (0=disabled)")
	c.sni = fs.String("sni", "", "SNI (Server Name Indication) for TLS certificate verification")
	c.lbs = fs.String("lbs", "", "Load balancing strategy: rr (round-robin), random (default: rr)")
	c.min = fs.String("min", "", "Minimum pool capacity (adaptive lower bound)")
	c.mode = fs.String("mode", "", "Connection mode: 0=auto, 1=single-connection, 2=tunnel pool")
	c.dial = fs.String("dial", "", "Outbound source IP for connecting to server (bind to specific interface)")
	c.read = fs.String("read", "", "Read timeout in seconds for idle connections (0=disabled)")
	c.rate = fs.String("rate", "", "Bandwidth rate limit in Mbps (per-connection, 0=unlimited)")
	c.slot = fs.String("slot", "", "Maximum concurrent connection slots (0=unlimited)")
	c.proxy = fs.String("proxy", "", "Enable PROXY protocol v1 support (true/false)")
	c.block = fs.String("block", "", "Block protocols: tcp, udp, or both")
	c.notcp = fs.String("notcp", "", "Disable TCP protocol support (true/false)")
	c.noudp = fs.String("noudp", "", "Disable UDP protocol support (true/false)")
}

func (c *commandLine) addMasterFlags(fs *flag.FlagSet) {
	c.tunnelAddr = fs.String("tunnel-addr", "", "Master API listening address (e.g., 0.0.0.0, localhost)")
	c.tunnelPort = fs.String("tunnel-port", "", "Master API listening port number")
	c.log = fs.String("log", "", "Log level: none, debug, warn, error, event")
	c.tls = fs.String("tls", "", "TLS mode: 0=none (plain HTTP), 1=self-signed RAM cert, 2=file-based cert")
	c.crt = fs.String("crt", "", "Certificate file path for API server (for tls=2, X509 PEM format)")
	c.key = fs.String("key", "", "Private key file path for API server (for tls=2, PEM format)")
}

func (c *commandLine) buildQuery() url.Values {
	query := url.Values{}

	if c.log != nil && *c.log != "" {
		query.Set("log", *c.log)
	}
	if c.dns != nil && *c.dns != "" {
		query.Set("dns", *c.dns)
	}
	if c.sni != nil && *c.sni != "" {
		query.Set("sni", *c.sni)
	}
	if c.lbs != nil && *c.lbs != "" {
		query.Set("lbs", *c.lbs)
	}
	if c.min != nil && *c.min != "" {
		query.Set("min", *c.min)
	}
	if c.max != nil && *c.max != "" {
		query.Set("max", *c.max)
	}
	if c.mode != nil && *c.mode != "" {
		query.Set("mode", *c.mode)
	}
	if c.pool != nil && *c.pool != "" {
		query.Set("type", *c.pool)
	}
	if c.tls != nil && *c.tls != "" {
		query.Set("tls", *c.tls)
	}
	if c.crt != nil && c.key != nil && c.tls != nil && *c.tls == "2" {
		if *c.crt != "" {
			query.Set("crt", *c.crt)
		}
		if *c.key != "" {
			query.Set("key", *c.key)
		}
	}
	if c.dial != nil && *c.dial != "" {
		query.Set("dial", *c.dial)
	}
	if c.read != nil && *c.read != "" {
		query.Set("read", *c.read)
	}
	if c.rate != nil && *c.rate != "" {
		query.Set("rate", *c.rate)
	}
	if c.slot != nil && *c.slot != "" {
		query.Set("slot", *c.slot)
	}
	if c.proxy != nil && *c.proxy != "" {
		query.Set("proxy", *c.proxy)
	}
	if c.block != nil && *c.block != "" {
		query.Set("block", *c.block)
	}
	if c.notcp != nil && *c.notcp != "" {
		query.Set("notcp", *c.notcp)
	}
	if c.noudp != nil && *c.noudp != "" {
		query.Set("noudp", *c.noudp)
	}

	return query
}

func (c *commandLine) buildHost() string {
	addr := ""
	if c.tunnelAddr != nil && *c.tunnelAddr != "" {
		addr = *c.tunnelAddr
	}
	if c.tunnelPort != nil && *c.tunnelPort != "" {
		if addr != "" {
			return fmt.Sprintf("%s:%s", addr, *c.tunnelPort)
		}
		return ":" + *c.tunnelPort
	}
	return addr
}

func (c *commandLine) buildPath() string {
	if c.targets != nil && *c.targets != "" {
		return "/" + *c.targets
	}
	addr := ""
	if c.targetAddr != nil && *c.targetAddr != "" {
		addr = *c.targetAddr
	}
	if c.targetPort != nil && *c.targetPort != "" {
		if addr != "" {
			return fmt.Sprintf("/%s:%s", addr, *c.targetPort)
		}
		return "/:" + *c.targetPort
	}
	if addr != "" {
		return "/" + addr
	}
	return "/"
}

func (c *commandLine) buildUserInfo() *url.Userinfo {
	if c.password != nil && *c.password != "" {
		return url.User(*c.password)
	}
	return nil
}

func (c *commandLine) parseServerCommand(args []string) (*url.URL, error) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	c.addServerFlags(fs)

	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: nodepass server [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &url.URL{
		Scheme:   "server",
		User:     c.buildUserInfo(),
		Host:     c.buildHost(),
		Path:     c.buildPath(),
		RawQuery: c.buildQuery().Encode(),
	}, nil
}

func (c *commandLine) parseClientCommand(args []string) (*url.URL, error) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	c.addClientFlags(fs)

	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: nodepass client [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &url.URL{
		Scheme:   "client",
		User:     c.buildUserInfo(),
		Host:     c.buildHost(),
		Path:     c.buildPath(),
		RawQuery: c.buildQuery().Encode(),
	}, nil
}

func (c *commandLine) parseMasterCommand(args []string) (*url.URL, error) {
	fs := flag.NewFlagSet("master", flag.ExitOnError)
	c.addMasterFlags(fs)

	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: nodepass master [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &url.URL{
		Scheme:   "master",
		Host:     c.buildHost(),
		RawQuery: c.buildQuery().Encode(),
	}, nil
}

func (c *commandLine) printHelp() {
	fmt.Fprintf(os.Stdout, `NodePass - Universal TCP/UDP Tunneling Solution

Usage:
  nodepass <command> [options]
  nodepass <url>

Commands:
  server    Start a NodePass server
  client    Start a NodePass client
  master    Start a NodePass master
  help      Show this helper message
  version   Show version information

`)
}
