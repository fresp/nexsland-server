// Package todo holds the synced todo model (contract version 2) and its validation.
package todo

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Todo is one synced task.
type Todo struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Day       string    `json:"day"`
	Minutes   *int      `json:"minutes"`
	Done      bool      `json:"done"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Deleted   bool      `json:"deleted"`
	Seq       int64     `json:"seq"`
}

const (
	MaxTitle  = 200
	dayLayout = "2006-01-02"
)

// ValidationError is a user-facing validation failure.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

func invalid(field, format string, args ...any) error {
	return &ValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}

// IsValidation reports whether err is a ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

// NormalizeTitle trims a title and checks its length.
func NormalizeTitle(s string) (string, error) {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	if n == 0 {
		return "", invalid("title", "must not be empty")
	}
	if n > MaxTitle {
		return "", invalid("title", "must be at most %d characters", MaxTitle)
	}
	return s, nil
}

// ParseDay checks a YYYY-MM-DD calendar date.
func ParseDay(s string) (time.Time, error) {
	t, err := time.Parse(dayLayout, s)
	if err != nil || t.Format(dayLayout) != s {
		return time.Time{}, invalid("day", "must be a calendar date in YYYY-MM-DD form, got %q", s)
	}
	if t.Year() < 2000 || t.Year() > 2200 {
		return time.Time{}, invalid("day", "year out of range")
	}
	return t, nil
}

// ValidMinutes checks a minutes-of-day value.
func ValidMinutes(m *int) error {
	if m != nil && (*m < 0 || *m > 1439) {
		return invalid("minutes", "must be between 0 and 1439 or null")
	}
	return nil
}

// ParseTime parses HH:MM into minutes of day.
func ParseTime(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if ok && len(h) >= 1 && len(h) <= 2 && len(m) == 2 {
		hh, err1 := strconv.Atoi(h)
		mm, err2 := strconv.Atoi(m)
		if err1 == nil && err2 == nil && hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59 {
			return hh*60 + mm, nil
		}
	}
	return 0, invalid("time", "must be HH:MM in 24-hour form, got %q", s)
}

// FormatTime renders minutes of day as HH:MM.
func FormatTime(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

// ValidID checks that s is a canonical UUIDv7.
func ValidID(s string) error {
	u, err := uuid.Parse(s)
	if err != nil || u.String() != s || u.Version() != 7 {
		return invalid("id", "must be a lowercase UUIDv7")
	}
	return nil
}

// NewID returns a fresh UUIDv7.
func NewID() string { return uuid.Must(uuid.NewV7()).String() }

// Normalize validates every synced field and canonicalizes title and timestamps.
// It does not look at Seq, which the server owns.
func (t *Todo) Normalize() error {
	if err := ValidID(t.ID); err != nil {
		return err
	}
	title, err := NormalizeTitle(t.Title)
	if err != nil {
		return err
	}
	t.Title = title
	if _, err := ParseDay(t.Day); err != nil {
		return err
	}
	if err := ValidMinutes(t.Minutes); err != nil {
		return err
	}
	if t.UpdatedAt.IsZero() {
		return invalid("updated_at", "is required")
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = t.UpdatedAt
	}
	t.CreatedAt = Millis(t.CreatedAt)
	t.UpdatedAt = Millis(t.UpdatedAt)
	return nil
}

// Millis truncates t to millisecond precision in UTC, the stored precision.
func Millis(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

// Clock knows the owner's time zone.
type Clock struct {
	Loc *time.Location
	Now func() time.Time
}

// Today returns today's date in the owner's zone as YYYY-MM-DD.
func (c Clock) Today() string { return c.now().In(c.Loc).Format(dayLayout) }

// AddDays shifts a YYYY-MM-DD date by n calendar days.
func AddDays(day string, n int) string {
	t, err := time.Parse(dayLayout, day)
	if err != nil {
		return day
	}
	return t.AddDate(0, 0, n).Format(dayLayout)
}

// NowUTC returns the current instant at stored precision.
func (c Clock) NowUTC() time.Time { return Millis(c.now()) }

func (c Clock) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
