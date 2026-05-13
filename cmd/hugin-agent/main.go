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
	"errors"
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

	// HTTP / NATS modes can run side by side. --no-listen disables HTTP;
	// --no-nats disables NATS. By default both run when configured.
	noListen := flag.Bool("no-listen", false, "Don't start the local HTTP listener")
	noNATS := flag.Bool("no-nats", false, "Don't connect to NATS (even if creds.json exists)")

	// NATS-mode registration. --register flips the binary into a
	// one-shot mode that POSTs /v1/agents/register to the API and
	// writes the resulting creds to disk, then exits.
	registerMode := flag.Bool("register", false, "Register with hugin-api and write creds.json. Requires --gh-token.")
	apiBaseFlag := flag.String("api-url", "https://api.hugin.sourceful-labs.net", "Hugin API base (env: HUGIN_API_URL)")
	ghTokenFlag := flag.String("gh-token", "", "GitHub OAuth token used for --register only (env: HUGIN_GH_TOKEN)")
	credsPathFlag := flag.String("creds", "", "Path to NATS creds.json (default: $XDG_CONFIG_HOME/hugin-agent/creds.json)")

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
	if v := os.Getenv("HUGIN_API_URL"); v != "" {
		*apiBaseFlag = v
	}
	if v := os.Getenv("HUGIN_GH_TOKEN"); v != "" {
		*ghTokenFlag = v
	}
	if v := os.Getenv("HUGIN_AGENT_REGISTER"); v == "1" || v == "true" {
		*registerMode = true
	}

	credsPath := *credsPathFlag
	if credsPath == "" {
		credsPath = defaultCredsPath()
	}

	// --register is a one-shot: hit the API, write creds, exit.
	// Done up here so the rest of the bootstrap doesn't touch
	// listener / NATS state we'll never use in this run.
	if *registerMode {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := registerWithAPI(ctx, *apiBaseFlag, *ghTokenFlag)
		if err != nil {
			log.Fatalf("register: %v", err)
		}
		if err := saveCreds(credsPath, c); err != nil {
			log.Fatalf("write creds: %v", err)
		}

		// Build the workbench deep-link for the *remote-pair* flow.
		// settings.html ingests #pair_agent_id=…&kind=remote and
		// calls /v1/agents/{id}/owner-creds to mint matching
		// OWNER-role credentials for the browser side. Without this,
		// the user would have no obvious way to tell the workbench
		// which agent_id to bind to.
		pairURL := *pairingPage + "#pair_agent_id=" +
			url.QueryEscape(c.AgentID) + "&kind=remote"

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "  Registered as agent %s\n", c.AgentID)
		fmt.Fprintf(os.Stderr, "  Creds written to %s\n", credsPath)
		fmt.Fprintf(os.Stderr, "  NATS URL: %s\n", c.NATSURL)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Now pair the workbench to this agent:")
		fmt.Fprintf(os.Stderr, "    %s\n", pairURL)
		fmt.Fprintln(os.Stderr, "")
		if !*noBrowser && openBrowser(pairURL) {
			fmt.Fprintln(os.Stderr, "  Opened your browser to finish pairing.")
		} else {
			fmt.Fprintln(os.Stderr, "  Open the URL above to finish pairing,")
			fmt.Fprintln(os.Stderr, "  or run `hugin-agent` (no flags) to start the agent now.")
		}
		fmt.Fprintln(os.Stderr, "")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("signal received, shutting down")
		cancel()
	}()

	// --- HTTP listener (legacy local-only mode) ---
	var (
		srv      *http.Server
		listener net.Listener
	)
	if !*noListen {
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
		var err error
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("listen %s: %v", addr, err)
		}
		srv = &http.Server{
			Handler:     handler,
			ReadTimeout: 60 * time.Second,
		}

		pairingDeepLink := fmt.Sprintf("%s#agent_url=%s&token=%s",
			*pairingPage,
			url.QueryEscape(fmt.Sprintf("http://%s", addr)),
			url.QueryEscape(token),
		)

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

		go func() {
			if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Fatalf("serve: %v", err)
			}
		}()
	}

	// --- NATS mode (remote agent) ---
	var runner *natsRunner
	if !*noNATS {
		creds, err := loadCreds(credsPath)
		switch {
		case err == nil:
			warnIfCredsNearExpiry(creds, time.Now())
			runner, err = connectNATS(ctx, creds, log.Default(), version)
			if err != nil {
				log.Printf("nats: connect failed (continuing in HTTP-only mode): %v", err)
				runner = nil
			} else {
				go func() {
					if err := runner.run(ctx); err != nil {
						log.Printf("nats: run loop exited: %v", err)
					}
				}()
			}
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(os.Stderr, "  NATS: no creds at %s — run with --register --gh-token=<gh> to enable remote mode\n", credsPath)
		default:
			log.Printf("nats: read creds: %v (HTTP-only)", err)
		}
	}

	// At least one transport must be running.
	if *noListen && runner == nil {
		log.Fatal("both HTTP and NATS are disabled or unavailable — nothing to do")
	}

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if srv != nil {
		_ = srv.Shutdown(shutdownCtx)
	}
	if runner != nil {
		runner.close()
	}
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
