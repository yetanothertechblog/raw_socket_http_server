// Package orders is a small CRUD service over a SQLite-backed order book.
// It exists to give the HTTP/TLS/TCP stack something real to push bytes
// through end-to-end, not as a serious order management system.
package orders

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Order struct {
	ID         int64     `json:"id"`
	Customer   string    `json:"customer"`
	Item       string    `json:"item"`
	Quantity   int       `json:"quantity"`
	PriceCents int       `json:"price_cents"`
	CreatedAt  time.Time `json:"created_at"`
}

// ErrNotFound is returned by Get when no row matches the requested id.
var ErrNotFound = errors.New("orders: not found")

const schema = `
CREATE TABLE IF NOT EXISTS orders (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    customer     TEXT    NOT NULL,
    item         TEXT    NOT NULL,
    quantity     INTEGER NOT NULL,
    price_cents  INTEGER NOT NULL,
    created_at   TEXT    NOT NULL
);
`

type Store struct {
	db *sql.DB
}

// NewStore opens a SQLite database at dsn (use ":memory:" for a fresh
// in-process DB) and applies the schema. The returned Store owns the
// underlying *sql.DB.
func NewStore(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// :memory: databases are per-connection; pin to a single conn so all
	// queries see the same schema.
	if dsn == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Create inserts a new order and returns it with ID and CreatedAt populated.
func (s *Store) Create(o Order) (Order, error) {
	o.CreatedAt = time.Now().UTC()
	res, err := s.db.Exec(
		`INSERT INTO orders (customer, item, quantity, price_cents, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		o.Customer, o.Item, o.Quantity, o.PriceCents,
		o.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return Order{}, fmt.Errorf("insert order: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Order{}, fmt.Errorf("last insert id: %w", err)
	}
	o.ID = id
	return o, nil
}

func (s *Store) Get(id int64) (Order, error) {
	row := s.db.QueryRow(
		`SELECT id, customer, item, quantity, price_cents, created_at
		 FROM orders WHERE id = ?`, id)
	return scanOrder(row)
}

func (s *Store) List() ([]Order, error) {
	rows, err := s.db.Query(
		`SELECT id, customer, item, quantity, price_cents, created_at
		 FROM orders ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list orders: %w", err)
	}
	defer rows.Close()

	var out []Order
	for rows.Next() {
		o, err := scanOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows so the column-mapping
// logic is shared between Get (single row) and List (iteration).
type scanner interface {
	Scan(dest ...any) error
}

func scanOrder(s scanner) (Order, error) {
	var o Order
	var createdAt string
	err := s.Scan(&o.ID, &o.Customer, &o.Item, &o.Quantity, &o.PriceCents, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Order{}, ErrNotFound
	}
	if err != nil {
		return Order{}, fmt.Errorf("scan order: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Order{}, fmt.Errorf("parse created_at: %w", err)
	}
	o.CreatedAt = t
	return o, nil
}
