package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/fresp/nexsland-server/internal/todo"
)

// Op kinds.
const (
	OpUpsert = "upsert"
	OpDelete = "delete"
)

// Op is one validated write. For OpDelete only Todo.ID and Todo.UpdatedAt matter.
type Op struct {
	Kind string
	Todo todo.Todo
}

// Result statuses.
const (
	StatusApplied = "applied"
	StatusStale   = "stale"
)

// Result is the outcome of one op. Todo is the stored row after the op: the new
// row when applied, the winning row when stale.
type Result struct {
	ID     string    `json:"id"`
	Status string    `json:"status"`
	Todo   todo.Todo `json:"todo"`
}

const todoCols = "id, title, day, minutes, done, created_at, updated_at, deleted, seq"

type scanner interface{ Scan(...any) error }

func scanTodo(r scanner) (todo.Todo, error) {
	var t todo.Todo
	var minutes sql.NullInt64
	var created, updated int64
	err := r.Scan(&t.ID, &t.Title, &t.Day, &minutes, &t.Done, &created, &updated, &t.Deleted, &t.Seq)
	if err != nil {
		return t, err
	}
	if minutes.Valid {
		m := int(minutes.Int64)
		t.Minutes = &m
	}
	t.CreatedAt = msToTime(created)
	t.UpdatedAt = msToTime(updated)
	return t, nil
}

func getTodo(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, userID int64, id string) (todo.Todo, error) {
	t, err := scanTodo(q.QueryRowContext(ctx, "SELECT "+todoCols+" FROM todos WHERE user_id = ? AND id = ?", userID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func nextSeq(ctx context.Context, tx *sql.Tx) (int64, error) {
	var v int64
	err := tx.QueryRowContext(ctx, "UPDATE counters SET value = value + 1 WHERE name = 'seq' RETURNING value").Scan(&v)
	return v, err
}

// ApplyOps applies ops in one transaction with last-write-wins by updated_at.
// Ops must already be validated.
func (s *Store) ApplyOps(ctx context.Context, userID int64, ops []Op) ([]Result, error) {
	var results []Result
	err := s.tx(ctx, func(tx *sql.Tx) error {
		results = make([]Result, 0, len(ops))
		for _, op := range ops {
			r, err := applyOp(ctx, tx, userID, op)
			if err != nil {
				return err
			}
			results = append(results, r)
		}
		return nil
	})
	return results, err
}

func applyOp(ctx context.Context, tx *sql.Tx, userID int64, op Op) (Result, error) {
	in := op.Todo
	cur, err := getTodo(ctx, tx, userID, in.ID)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Result{}, err
	}
	if exists && !in.UpdatedAt.After(cur.UpdatedAt) {
		return Result{ID: in.ID, Status: StatusStale, Todo: cur}, nil
	}
	next := in
	switch op.Kind {
	case OpDelete:
		if exists {
			next = cur
		} else {
			next = todo.Todo{ID: in.ID, CreatedAt: in.UpdatedAt}
		}
		next.Deleted = true
		next.UpdatedAt = in.UpdatedAt
	case OpUpsert:
		if exists {
			next.CreatedAt = cur.CreatedAt
		}
	default:
		return Result{}, errors.New("unknown op " + op.Kind)
	}
	seq, err := nextSeq(ctx, tx)
	if err != nil {
		return Result{}, err
	}
	next.Seq = seq
	var minutes any
	if next.Minutes != nil {
		minutes = *next.Minutes
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO todos (user_id, `+todoCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, id) DO UPDATE SET title = excluded.title, day = excluded.day,
			minutes = excluded.minutes, done = excluded.done, created_at = excluded.created_at,
			updated_at = excluded.updated_at, deleted = excluded.deleted, seq = excluded.seq`,
		userID, next.ID, next.Title, next.Day, minutes, next.Done,
		next.CreatedAt.UnixMilli(), next.UpdatedAt.UnixMilli(), next.Deleted, next.Seq)
	if err != nil {
		return Result{}, err
	}
	return Result{ID: next.ID, Status: StatusApplied, Todo: next}, nil
}

// Mutate reads a live (not deleted) todo, lets fn change it and stores it as an
// upsert stamped with now. It returns ErrNotFound for missing or deleted todos.
// fn may return an error to abort.
func (s *Store) Mutate(ctx context.Context, userID int64, id string, now time.Time, fn func(*todo.Todo) error) (todo.Todo, error) {
	var out todo.Todo
	err := s.tx(ctx, func(tx *sql.Tx) error {
		cur, err := getTodo(ctx, tx, userID, id)
		if err != nil {
			return err
		}
		if cur.Deleted {
			return ErrNotFound
		}
		if err := fn(&cur); err != nil {
			return err
		}
		cur.UpdatedAt = laterThan(now, cur.UpdatedAt)
		r, err := applyOp(ctx, tx, userID, Op{Kind: OpUpsert, Todo: cur})
		out = r.Todo
		return err
	})
	return out, err
}

// Delete tombstones a live todo, stamped with now.
func (s *Store) Delete(ctx context.Context, userID int64, id string, now time.Time) (todo.Todo, error) {
	var out todo.Todo
	err := s.tx(ctx, func(tx *sql.Tx) error {
		cur, err := getTodo(ctx, tx, userID, id)
		if err != nil {
			return err
		}
		if cur.Deleted {
			return ErrNotFound
		}
		r, err := applyOp(ctx, tx, userID, Op{Kind: OpDelete, Todo: todo.Todo{ID: id, UpdatedAt: laterThan(now, cur.UpdatedAt)}})
		out = r.Todo
		return err
	})
	return out, err
}

// laterThan returns now, or prev+1ms if a client stamped prev in the future,
// so a server-side write always wins over the row it was based on.
func laterThan(now, prev time.Time) time.Time {
	now = todo.Millis(now)
	if !now.After(prev) {
		return prev.Add(time.Millisecond)
	}
	return now
}

// Get returns one todo, including tombstones.
func (s *Store) Get(ctx context.Context, userID int64, id string) (todo.Todo, error) {
	return getTodo(ctx, s.db, userID, id)
}

// Changes returns up to limit todos with seq > since, ordered by seq, and
// whether more remain.
func (s *Store) Changes(ctx context.Context, userID, since int64, limit int) ([]todo.Todo, bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+todoCols+" FROM todos WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT ?",
		userID, since, limit+1)
	if err != nil {
		return nil, false, err
	}
	out, err := collect(rows)
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// MaxSeq returns the current value of the sync cursor.
func (s *Store) MaxSeq(ctx context.Context) (int64, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, "SELECT value FROM counters WHERE name = 'seq'").Scan(&v)
	return v, err
}

// ListDays returns live todos with from <= day <= to, plus (if overdueBefore is
// not empty) unfinished todos with day < overdueBefore. Ordered by day, then
// timed before untimed, then by time and creation.
func (s *Store) ListDays(ctx context.Context, userID int64, from, to string, includeDone bool, overdueBefore string) ([]todo.Todo, error) {
	q := "SELECT " + todoCols + ` FROM todos WHERE user_id = ? AND deleted = 0 AND (
		(day BETWEEN ? AND ? AND (? OR done = 0))
		OR (? != '' AND day < ? AND done = 0))
		ORDER BY day, minutes IS NULL, minutes, created_at`
	rows, err := s.db.QueryContext(ctx, q, userID, from, to, includeDone, overdueBefore, overdueBefore)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

func collect(rows *sql.Rows) ([]todo.Todo, error) {
	defer rows.Close()
	out := []todo.Todo{}
	for rows.Next() {
		t, err := scanTodo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
