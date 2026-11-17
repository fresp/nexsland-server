package todo

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeTitle(t *testing.T) {
	if s, err := NormalizeTitle("  buy milk \n"); err != nil || s != "buy milk" {
		t.Fatalf("got %q %v", s, err)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("é", 201)} {
		if _, err := NormalizeTitle(bad); !IsValidation(err) {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := NormalizeTitle(strings.Repeat("é", 200)); err != nil {
		t.Errorf("200 runes rejected: %v", err)
	}
}

func TestParseDay(t *testing.T) {
	for _, ok := range []string{"2026-11-17", "2028-02-29"} {
		if _, err := ParseDay(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"2026-02-29", "2026-13-01", "2026-1-01", "17-11-2026", "2026-11-17T00:00:00Z", "", "1999-12-31"} {
		if _, err := ParseDay(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseTime(t *testing.T) {
	cases := map[string]int{"09:00": 540, "9:05": 545, "00:00": 0, "23:59": 1439}
	for in, want := range cases {
		if got, err := ParseTime(in); err != nil || got != want {
			t.Errorf("%s = %d %v, want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"24:00", "12:60", "12", "12:5", "-1:00", "ab:cd", "9:00am"} {
		if _, err := ParseTime(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if FormatTime(545) != "09:05" {
		t.Error("FormatTime")
	}
}

func TestValidMinutes(t *testing.T) {
	for _, m := range []int{-1, 1440} {
		if ValidMinutes(&m) == nil {
			t.Errorf("%d accepted", m)
		}
	}
	if ValidMinutes(nil) != nil {
		t.Error("nil rejected")
	}
}

func TestValidID(t *testing.T) {
	if err := ValidID(NewID()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "not-a-uuid", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", strings.ToUpper(NewID())} {
		if ValidID(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalize(t *testing.T) {
	upd := time.Date(2026, 11, 17, 1, 2, 3, 456789000, time.FixedZone("x", 7*3600))
	td := Todo{ID: NewID(), Title: " a ", Day: "2026-11-17", UpdatedAt: upd}
	if err := td.Normalize(); err != nil {
		t.Fatal(err)
	}
	if td.Title != "a" || !td.CreatedAt.Equal(td.UpdatedAt) || td.UpdatedAt.Nanosecond() != 456000000 || td.UpdatedAt.Location() != time.UTC {
		t.Fatalf("%+v", td)
	}
	td.UpdatedAt = time.Time{}
	if td.Normalize() == nil {
		t.Fatal("missing updated_at accepted")
	}
}

func TestTodayInZone(t *testing.T) {
	jkt, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		t.Fatal(err)
	}
	// 18:30 UTC on the 16th is 01:30 on the 17th in Jakarta (UTC+7).
	c := Clock{Loc: jkt, Now: func() time.Time { return time.Date(2026, 11, 16, 18, 30, 0, 0, time.UTC) }}
	if c.Today() != "2026-11-17" {
		t.Fatalf("today = %s", c.Today())
	}
	ny, _ := time.LoadLocation("America/New_York")
	c.Loc = ny
	if c.Today() != "2026-11-16" {
		t.Fatalf("today in NY = %s", c.Today())
	}
	if AddDays("2026-12-31", 1) != "2027-01-01" || AddDays("2028-02-28", 1) != "2028-02-29" {
		t.Fatal("AddDays")
	}
}
