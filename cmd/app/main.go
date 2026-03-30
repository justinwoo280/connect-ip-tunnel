package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"connect-ip-tunnel/engine"
	"connect-ip-tunnel/option"
	"connect-ip-tunnel/server"
)

func main() {
	configPath := flag.String("c", "", "config file path (JSON)")
	flag.Parse()

	cfg, err := option.LoadOrDefault(*configPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	log.Printf("connect-ip-tunnel starting in %s mode", cfg.Mode)

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

	log.Printf("server started, press Ctrl+C to exit")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("signal received, shutting down server")
}
