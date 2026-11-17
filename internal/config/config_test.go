package config

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestFromEnv(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"NEXSLAND_PUBLIC_URL": "https://nexsland.example.com/", "NEXSLAND_TZ": "Asia/Jakarta",
		"NEXSLAND_DB": "/data/n.db", "NEXSLAND_LISTEN": ":8080", "NEXSLAND_LOG_LEVEL": "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Public() != "https://nexsland.example.com" || !c.Secure() || c.Location.String() != "Asia/Jakarta" || c.LogLevel.String() != "DEBUG" {
		t.Fatalf("%+v", c)
	}
	_, err = FromEnv(env(map[string]string{"NEXSLAND_TZ": "Mars/Base"}))
	for _, want := range []string{"NEXSLAND_PUBLIC_URL is required", "NEXSLAND_DB is required", "NEXSLAND_LISTEN is required", "NEXSLAND_TZ"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestParsePublicURL(t *testing.T) {
	for _, ok := range []string{"https://a.example", "http://localhost:8080", "http://127.0.0.1:1"} {
		if _, err := ParsePublicURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://a.example", "a.example", "https://a.example/?x=1", "https://u:p@a.example"} {
		if _, err := ParsePublicURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
