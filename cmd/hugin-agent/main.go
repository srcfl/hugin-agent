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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
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
	noBrowser := flag.Bool("no-browser", false, "Don't auto-open the pairing page in a browser")
	pairingPage := flag.String("pairing-url", "https://hugin.sourceful-labs.net/settings.html", "Web app settings page (rarely overridden — useful for self-hosted Hugin)")
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

	// Build the deep-link to the web app's pairing page. Token + URL go
	// in the URL fragment so they never reach Cloudflare's access logs
	// — fragments aren't sent to servers. settings.html parses them and
	// auto-fills the form (then scrubs the URL).
	pairingDeepLink := fmt.Sprintf("%s#agent_url=%s&token=%s",
		*pairingPage,
		url.QueryEscape(fmt.Sprintf("http://%s", addr)),
		url.QueryEscape(token),
	)

	// Print pairing details to stderr (so stdout stays clean for tooling).
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "  Hugin agent %s\n", version)
	fmt.Fprintf(os.Stderr, "  Listening on %s\n", displayURL)
	fmt.Fprintf(os.Stderr, "  Pairing token: %s\n", token)
	fmt.Fprintln(os.Stderr, "")
	if !*noBrowser && openBrowser(pairingDeepLink) {
		fmt.Fprintln(os.Stderr, "  Opened your browser to finish pairing.")
		fmt.Fprintln(os.Stderr, "  If nothing happened, paste this URL in manually:")
		fmt.Fprintf(os.Stderr, "    %s\n", pairingDeepLink)
	} else {
		fmt.Fprintln(os.Stderr, "  Pair manually:")
		fmt.Fprintf(os.Stderr, "    %s\n", pairingDeepLink)
	}
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

// openBrowser tries to open the user's default browser to the given URL.
// Returns true on success, false otherwise. Best-effort — we still print
// the URL to stderr regardless so headless setups can copy it manually.
func openBrowser(target string) bool {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	args = append(args, target)
	c := exec.Command(cmd, args...)
	c.Stdout = nil
	c.Stderr = nil
	return c.Start() == nil
}
