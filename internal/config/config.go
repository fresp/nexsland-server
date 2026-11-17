// Package config reads the server configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is the runtime configuration.
type Config struct {
	PublicURL *url.URL // no trailing slash, no query
	Location  *time.Location
	DBPath    string
	Listen    string
	LogLevel  slog.Level
}

// Public returns the public base URL as a string without a trailing slash.
func (c *Config) Public() string { return c.PublicURL.String() }

// Secure reports whether the public URL is HTTPS.
func (c *Config) Secure() bool { return c.PublicURL.Scheme == "https" }

// FromEnv reads NEXSLAND_* variables. lookup is os.LookupEnv in production.
func FromEnv(lookup func(string) (string, bool)) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	var errs []error
	get := func(name string) string {
		v, ok := lookup(name)
		v = strings.TrimSpace(v)
		if !ok || v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
		return v
	}
	c := &Config{}
	if raw := get("NEXSLAND_PUBLIC_URL"); raw != "" {
		u, err := ParsePublicURL(raw)
		if err != nil {
			errs = append(errs, err)
		}
		c.PublicURL = u
	}
	if tz := get("NEXSLAND_TZ"); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			errs = append(errs, fmt.Errorf("NEXSLAND_TZ: %w", err))
		}
		c.Location = loc
	}
	c.DBPath = get("NEXSLAND_DB")
	c.Listen = get("NEXSLAND_LISTEN")
	if v, ok := lookup("NEXSLAND_LOG_LEVEL"); ok && strings.TrimSpace(v) != "" {
		if err := c.LogLevel.UnmarshalText([]byte(strings.TrimSpace(v))); err != nil {
			errs = append(errs, fmt.Errorf("NEXSLAND_LOG_LEVEL: %w", err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// ParsePublicURL validates the externally visible base URL. It must be HTTPS
// unless the host is loopback (local testing).
func ParsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("NEXSLAND_PUBLIC_URL must be an absolute URL like https://todo.example.com, got %q", raw)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && IsLoopbackHost(u.Hostname())) {
		return nil, fmt.Errorf("NEXSLAND_PUBLIC_URL must use https (http is allowed only for localhost), got %q", raw)
	}
	return u, nil
}

// IsLoopbackHost reports whether host is localhost or a loopback IP.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
