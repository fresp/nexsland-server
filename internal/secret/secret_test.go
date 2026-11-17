package secret

import (
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	h, err := HashPassword("a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") || !VerifyPassword(h, "a long enough password") || VerifyPassword(h, "a long enough passwore") {
		t.Fatal("verify")
	}
	if VerifyPassword("garbage", "x") || VerifyPassword("", "") {
		t.Fatal("garbage hash verified")
	}
}

func TestUserCode(t *testing.T) {
	c := UserCode()
	if len(c) != 9 || c[4] != '-' || strings.ContainsAny(c, "AEIOUY") {
		t.Fatalf("code %q", c)
	}
	if NormalizeUserCode(" bcdf ghjk ") != "BCDF-GHJK" || NormalizeUserCode("bcd") != "" {
		t.Fatal("normalize")
	}
}

func TestTokenAndHash(t *testing.T) {
	a, b := Token("p_"), Token("p_")
	if a == b || !strings.HasPrefix(a, "p_") || len(a) != 45 || Hash(a) == Hash(b) || len(Hash(a)) != 64 {
		t.Fatal("token")
	}
}
