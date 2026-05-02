// Command hugin-agent is a thin local helper for the Hugin web app
// (https://hugin.sourceful-labs.net). It exposes a small HTTP protocol
// for LAN scanning, Modbus probing, and Lua-driver execution. The web
// app calls into it from the browser; auth is by a single Bearer token
// printed at startup. No state, no DB, no AI, no telemetry.
//
// Run: ./hugin-agent
// Pair: paste the printed URL + token into https://hugin.sourceful-labs.net/settings.html
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/srcfl/hugin-agent/internal/server"
)

// version is set by goreleaser via ldflags at release build time.
var version = "dev"

func main() {
	host := flag.String("host", "127.0.0.1", "HTTP bind host (use 127.0.0.1 unless you trust your LAN)")
	port := flag.Int("port", 19090, "HTTP port")
	tokenFlag := flag.String("token", "", "Pairing token. If empty, a random one is generated.")
	flag.Parse()

	if v := os.Getenv("HUGIN_AGENT_HOST"); v != "" {
		*host = v
	}
	if v := os.Getenv("HUGIN_AGENT_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			*port = p
		}
	}
	if v := os.Getenv("HUGIN_AGENT_TOKEN"); v != "" {
		*tokenFlag = v
	}

	token := *tokenFlag
	if token == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			log.Fatalf("random: %v", err)
		}
		token = hex.EncodeToString(buf)
	}

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	displayURL := fmt.Sprintf("http://%s", addr)
	if *host == "0.0.0.0" {
		displayURL = fmt.Sprintf("http://localhost:%d  (also reachable on your LAN — be careful)", *port)
	}

	handler := server.New(server.Config{
		Version: version,
		Token:   token,
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}

	srv := &http.Server{
		Handler:     handler,
		ReadTimeout: 60 * time.Second,
	}

	// Print pairing details to stderr (so stdout stays clean for tooling).
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  Hugin agent %s\n", version)
	fmt.Fprintf(os.Stderr, "  Listening on %s\n", displayURL)
	fmt.Fprintf(os.Stderr, "  Pairing token: %s\n", token)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  Pair this agent with the web app:")
	fmt.Fprintln(os.Stderr, "    1. Open https://hugin.sourceful-labs.net/settings.html")
	fmt.Fprintln(os.Stderr, "    2. Paste the URL above + this token")
	fmt.Fprintln(os.Stderr, "    3. Click 'Test connection' then 'Save pairing'")
	fmt.Fprintln(os.Stderr, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("signal received, shutting down")
		cancel()
	}()

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Println("shutdown complete")
}
