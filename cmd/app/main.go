package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connect-ip-tunnel/certsrv"
	"connect-ip-tunnel/engine"
	"connect-ip-tunnel/option"
	"connect-ip-tunnel/server"
)

// Version is set at build time via -ldflags "-X main.Version=<tag>"
var Version = "dev"

func main() {
	// 支持两种调用方式：
	//   connect-ip-tunnel --config foo.json        （无子命令）
	//   connect-ip-tunnel server --config foo.json  （有子命令，兼容 Docker CMD）
	//   connect-ip-tunnel client --config foo.json
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "server" || args[0] == "client") {
		args = args[1:] // 跳过子命令，只解析后面的 flags
	}

	fs := flag.NewFlagSet("connect-ip-tunnel", flag.ExitOnError)
	configPath := fs.String("config", "", "config file path (JSON)")
	fs.StringVar(configPath, "c", "", "config file path (JSON, shorthand for --config)")
	showVersion := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(args)

	if *showVersion {
		log.Printf("connect-ip-tunnel %s", Version)
		os.Exit(0)
	}

	cfg, err := option.LoadOrDefault(*configPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	log.Printf("connect-ip-tunnel %s starting in %s mode", Version, cfg.Mode)

	// 根据模式启动客户端或服务端
	if cfg.Mode == option.ModeClient {
		runClient(cfg.Client)
	} else {
		runServer(cfg.Server)
	}
}

func runClient(cfg option.ClientConfig) {
	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatalf("create client engine failed: %v", err)
	}

	if err := eng.Start(); err != nil {
		log.Fatalf("start client engine failed: %v", err)
	}
	defer func() {
		if err := eng.Close(); err != nil {
			log.Printf("close client engine warning: %v", err)
		}
	}()

	log.Printf("client started, press Ctrl+C to exit")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("signal received, shutting down client")
}

func runServer(cfg option.ServerConfig) {
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("create server failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("start server failed: %v", err)
	}
	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("close server warning: %v", err)
		}
	}()

	// 启动 certsrv（如果配置了监听地址）
	var cs *certsrv.Server
	if cfg.CertSrv.Listen != "" {
		cs, err = startCertSrv(cfg)
		if err != nil {
			log.Fatalf("start certsrv failed: %v", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := cs.Shutdown(ctx); err != nil {
				log.Printf("certsrv shutdown warning: %v", err)
			}
			cs.Close()
		}()
	}

	log.Printf("server started, press Ctrl+C to exit")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("signal received, shutting down server")
}

// startCertSrv 初始化并启动证书管理面板
func startCertSrv(cfg option.ServerConfig) (*certsrv.Server, error) {
	c := cfg.CertSrv

	// 默认值填充
	if c.DBPath == "" {
		c.DBPath = "/etc/connect-ip-tunnel/certsrv.db"
	}
	if c.CACertFile == "" {
		c.CACertFile = cfg.TLS.ClientCAFile
	}
	if c.TLSCert == "" {
		c.TLSCert = cfg.TLS.CertFile
	}
	if c.TLSKey == "" {
		c.TLSKey = cfg.TLS.KeyFile
	}

	if c.CACertFile == "" {
		return nil, fmt.Errorf("certsrv: ca_cert_file is required (or set tls.client_ca_file)")
	}
	if c.CAKeyFile == "" {
		return nil, fmt.Errorf("certsrv: ca_key_file is required")
	}

	cs, err := certsrv.New(certsrv.Config{
		Listen:     c.Listen,
		DBPath:     c.DBPath,
		CACertFile: c.CACertFile,
		CAKeyFile:  c.CAKeyFile,
		TLSCert:    c.TLSCert,
		TLSKey:     c.TLSKey,
	}, slog.Default())
	if err != nil {
		return nil, err
	}

	go func() {
		if err := cs.Start(); err != nil {
			slog.Error("certsrv stopped", "err", err)
		}
	}()

	log.Printf("certsrv listening on %s", c.Listen)
	return cs, nil
}
