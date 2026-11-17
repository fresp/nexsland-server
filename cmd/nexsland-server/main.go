// Command nexsland-server runs the Nexsland todo server and its admin CLI.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // the scratch/distroless image has no zoneinfo

	"golang.org/x/term"

	"github.com/fresp/nexsland-server/internal/config"
	"github.com/fresp/nexsland-server/internal/secret"
	"github.com/fresp/nexsland-server/internal/server"
	"github.com/fresp/nexsland-server/internal/store"
)

const usage = `Usage:
  nexsland-server serve                         run the server (default)
  nexsland-server owner set-password            set the owner password (reads stdin)
  nexsland-server oauth-client add NAME URI...  pre-register a public OAuth client
  nexsland-server migrate                       apply database migrations and exit
  nexsland-server version

Configuration comes from the environment; see README.md.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return serve()
	case "version", "--version":
		fmt.Println(server.Version)
		return nil
	case "migrate":
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		v, err := st.SchemaVersion(context.Background())
		fmt.Println("schema version", v)
		return err
	case "owner":
		if len(args) != 1 || args[0] != "set-password" {
			return errors.New("usage: nexsland-server owner set-password")
		}
		return setPassword()
	case "oauth-client":
		if len(args) < 3 || args[0] != "add" {
			return errors.New("usage: nexsland-server oauth-client add NAME REDIRECT_URI...")
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		id, err := server.NewCLIClient(context.Background(), st, args[1], args[2:])
		if err != nil {
			return err
		}
		fmt.Println("client_id:", id)
		fmt.Println("Public client: leave the client secret empty.")
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

// openStore needs only NEXSLAND_DB, so admin commands work without the full config.
func openStore() (*store.Store, error) {
	path := strings.TrimSpace(os.Getenv("NEXSLAND_DB"))
	if path == "" {
		return nil, errors.New("NEXSLAND_DB is required")
	}
	return store.Open(context.Background(), path)
}

func setPassword() error {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "New owner password (min 12 characters): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "Repeat: ")
		b2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if string(b) != string(b2) {
			return errors.New("passwords do not match")
		}
		pw = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no password on stdin")
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	hash, err := secret.HashPassword(pw)
	if err != nil {
		return err
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.SetPasswordHash(ctx, store.OwnerID, hash); err != nil {
		return err
	}
	if err := st.DeleteUserSessions(ctx, store.OwnerID); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Owner password set. Existing web sessions were signed out.")
	return nil
}

func serve() error {
	cfg, err := config.FromEnv(nil)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	v, _ := st.SchemaVersion(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(cfg, st, log, nil).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen, "public_url", cfg.Public(), "time_zone", cfg.Location.String(),
		"version", server.Version, "schema", v)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
