package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/fresp/nexsland-server/internal/todo"
)

var t0 = time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mk(id, title string, upd time.Time) todo.Todo {
	return todo.Todo{ID: id, Title: title, Day: "2026-11-18", UpdatedAt: upd, CreatedAt: upd}
}

func upsert(t *testing.T, s *Store, td todo.Todo) Result {
	t.Helper()
	r, err := s.ApplyOps(context.Background(), OwnerID, []Op{{Kind: OpUpsert, Todo: td}})
	if err != nil {
		t.Fatal(err)
	}
	return r[0]
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	v1, _ := s.SchemaVersion(ctx)
	upsert(t, s, mk(todo.NewID(), "a", t0))
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v2, _ := s.SchemaVersion(ctx)
	ms, _ := loadMigrations()
	if v1 != len(ms) || v2 != v1 {
		t.Fatalf("schema version %d then %d, want %d", v1, v2, len(ms))
	}
	if n, _ := s.MaxSeq(ctx); n != 1 {
		t.Fatalf("data lost across reopen: max seq %d", n)
	}
	var mode string
	_ = s.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.db.Exec("INSERT INTO schema_migrations VALUES (999, 'future', 0)")
	s.Close()
	if _, err := Open(ctx, path); err == nil {
		t.Fatal("opened a database with a newer schema")
	}
}

func TestLastWriteWins(t *testing.T) {
	s := open(t)
	id := todo.NewID()
	r := upsert(t, s, mk(id, "v1", t0))
	if r.Status != StatusApplied || r.Todo.Seq != 1 {
		t.Fatalf("first write: %+v", r)
	}
	r = upsert(t, s, mk(id, "older", t0.Add(-time.Second)))
	if r.Status != StatusStale || r.Todo.Title != "v1" {
		t.Fatalf("older write should be stale and return stored row: %+v", r)
	}
	r = upsert(t, s, mk(id, "same", t0))
	if r.Status != StatusStale {
		t.Fatalf("tie should keep stored row: %+v", r)
	}
	newer := mk(id, "v2", t0.Add(time.Second))
	newer.CreatedAt = t0.Add(time.Hour) // created_at is immutable
	r = upsert(t, s, newer)
	if r.Status != StatusApplied || r.Todo.Title != "v2" || r.Todo.Seq != 2 || !r.Todo.CreatedAt.Equal(t0) {
		t.Fatalf("newer write: %+v", r)
	}
}

func TestTombstones(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id := todo.NewID()
	upsert(t, s, mk(id, "a", t0))
	res, err := s.ApplyOps(ctx, OwnerID, []Op{{Kind: OpDelete, Todo: todo.Todo{ID: id, UpdatedAt: t0.Add(time.Second)}}})
	if err != nil || res[0].Status != StatusApplied || !res[0].Todo.Deleted || res[0].Todo.Title != "a" {
		t.Fatalf("delete: %+v %v", res, err)
	}
	// A stale edit does not revive it.
	if r := upsert(t, s, mk(id, "stale", t0.Add(500*time.Millisecond))); r.Status != StatusStale || !r.Todo.Deleted {
		t.Fatalf("stale edit after delete: %+v", r)
	}
	// Delete of an unknown id stores a tombstone so it propagates.
	unknown := todo.NewID()
	res, _ = s.ApplyOps(ctx, OwnerID, []Op{{Kind: OpDelete, Todo: todo.Todo{ID: unknown, UpdatedAt: t0}}})
	if res[0].Status != StatusApplied || !res[0].Todo.Deleted {
		t.Fatalf("unknown delete: %+v", res)
	}
	all, _, _ := s.Changes(ctx, OwnerID, 0, 100)
	if len(all) != 2 || !all[0].Deleted || !all[1].Deleted {
		t.Fatalf("changes should include tombstones: %+v", all)
	}
	// Tombstones are not listed, Mutate and Delete treat them as missing.
	list, _ := s.ListDays(ctx, OwnerID, "2000-01-01", "2100-01-01", true, "")
	if len(list) != 0 {
		t.Fatalf("list shows tombstones: %+v", list)
	}
	if _, err := s.Mutate(ctx, OwnerID, id, t0.Add(time.Hour), func(*todo.Todo) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mutate tombstone: %v", err)
	}
}

func TestBatchIsAtomic(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	ops := []Op{{Kind: OpUpsert, Todo: mk(todo.NewID(), "a", t0)}, {Kind: "bogus", Todo: mk(todo.NewID(), "b", t0)}}
	if _, err := s.ApplyOps(ctx, OwnerID, ops); err == nil {
		t.Fatal("expected error")
	}
	if n, _ := s.MaxSeq(ctx); n != 0 {
		t.Fatalf("partial batch committed, seq %d", n)
	}
}

func TestCursorPaging(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	ids := make([]string, 5)
	for i := range ids {
		ids[i] = todo.NewID()
		upsert(t, s, mk(ids[i], "t", t0))
	}
	// Re-editing the first moves it to the end of the change feed.
	upsert(t, s, mk(ids[0], "t2", t0.Add(time.Second)))
	var got []string
	since := int64(0)
	for pages := 0; ; pages++ {
		page, more, err := s.Changes(ctx, OwnerID, since, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, td := range page {
			if td.Seq <= since {
				t.Fatalf("seq not increasing: %d after %d", td.Seq, since)
			}
			since = td.Seq
			got = append(got, td.ID)
		}
		if !more {
			if pages != 2 {
				t.Fatalf("pages = %d, want 3", pages+1)
			}
			break
		}
	}
	want := append(ids[1:], ids[0])
	if len(got) != len(want) {
		t.Fatalf("got %d todos, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

func TestMutateStampsLaterThanStored(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id := todo.NewID()
	future := t0.Add(2 * time.Minute) // a client with a fast clock
	upsert(t, s, mk(id, "a", future))
	got, err := s.Mutate(ctx, OwnerID, id, t0, func(td *todo.Todo) error { td.Done = true; return nil })
	if err != nil || !got.Done || !got.UpdatedAt.After(future) {
		t.Fatalf("mutate: %+v %v", got, err)
	}
}

func TestListDaysOverdue(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	add := func(day string, done bool, minutes *int) {
		td := mk(todo.NewID(), day, t0)
		td.Day, td.Done, td.Minutes = day, done, minutes
		upsert(t, s, td)
	}
	nine := 540
	add("2026-11-10", false, nil) // overdue
	add("2026-11-10", true, nil)  // done in the past: hidden
	add("2026-11-17", false, nil)
	add("2026-11-17", false, &nine)
	add("2026-11-17", true, nil)
	add("2026-11-30", false, nil) // out of range
	list, err := s.ListDays(ctx, OwnerID, "2026-11-17", "2026-11-24", false, "2026-11-17")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Day != "2026-11-10" || list[1].Minutes == nil || list[2].Minutes != nil {
		t.Fatalf("list: %+v", list)
	}
	list, _ = s.ListDays(ctx, OwnerID, "2026-11-17", "2026-11-24", true, "")
	if len(list) != 3 {
		t.Fatalf("include_done without overdue: %d", len(list))
	}
}

func TestPairLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	p := PairRequest{DeviceCodeHash: "dc", UserCode: "ABCD-EFGH", DeviceName: "laptop", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.CreatePairRequest(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.CompletePair(ctx, "dc", Device{ID: "d1", UserID: OwnerID, Name: "laptop"}, "th"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("completed a pending pair: %v", err)
	}
	if err := s.DecidePair(ctx, "ABCD-EFGH", OwnerID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.CompletePair(ctx, "dc", Device{ID: "d1", UserID: OwnerID, Name: "laptop"}, "th"); err != nil {
		t.Fatal(err)
	}
	if err := s.CompletePair(ctx, "dc", Device{ID: "d2", UserID: OwnerID, Name: "laptop"}, "th2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delivered twice: %v", err)
	}
	if d, err := s.DeviceByToken(ctx, "th"); err != nil || d.ID != "d1" {
		t.Fatalf("device: %+v %v", d, err)
	}
	if err := s.RevokeDevice(ctx, OwnerID, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeviceByToken(ctx, "th"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked device still valid: %v", err)
	}
}

func TestRefreshReuseRevokesGrant(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.CreateClient(ctx, OAuthClient{ID: "c", Name: "Claude", RedirectURIs: []string{"https://x/cb"}, AuthMethod: "none", Source: "dcr"}); err != nil {
		t.Fatal(err)
	}
	g := Grant{ID: "g", UserID: OwnerID, ClientID: "c", Scope: "todos", Resource: "https://h/mcp"}
	exp := time.Now().Add(time.Minute)
	if err := s.CreateGrantWithCode(ctx, g, "code", "https://x/cb", "chal", exp); err != nil {
		t.Fatal(err)
	}
	ok := func(AuthCode) error { return nil }
	toks := []IssuedToken{{Hash: "a1", Kind: "access", ExpiresAt: exp}, {Hash: "r1", Kind: "refresh", ExpiresAt: exp}}
	if _, err := s.RedeemCode(ctx, "code", ok, toks); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemCode(ctx, "code", ok, nil); !errors.Is(err, ErrReplay) {
		t.Fatalf("code reuse: %v", err)
	}
	if _, _, err := s.AccessToken(ctx, "a1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("code reuse should revoke the grant: %v", err)
	}

	g.ID = "g2"
	_ = s.CreateGrantWithCode(ctx, g, "code2", "https://x/cb", "chal", exp)
	_, _ = s.RedeemCode(ctx, "code2", ok, []IssuedToken{{Hash: "r2", Kind: "refresh", ExpiresAt: exp}})
	okg := func(Grant) error { return nil }
	if _, err := s.RotateRefresh(ctx, "r2", okg, []IssuedToken{{Hash: "a3", Kind: "access", ExpiresAt: exp}, {Hash: "r3", Kind: "refresh", ExpiresAt: exp}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AccessToken(ctx, "a3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateRefresh(ctx, "r2", okg, nil); !errors.Is(err, ErrReplay) {
		t.Fatalf("refresh reuse: %v", err)
	}
	if _, _, err := s.AccessToken(ctx, "a3"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("refresh reuse should revoke the grant: %v", err)
	}
}
