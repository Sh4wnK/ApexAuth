// Package migrate runs the SQL migrations embedded in the binary. Files are
// named NNNN_name.up.sql and applied in order, each inside a transaction;
// schema_migrations tracks the latest applied version.
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"

	"github.com/Sh4wnK/ApexAuth/migrations"
	"github.com/jackc/pgx/v5"
)

var fileRe = regexp.MustCompile(`^(\d+)_[a-z0-9_]+\.up\.sql$`)

// Up applies all pending migrations on the given connection. It is safe to
// call concurrently from multiple processes: each migration version is
// recorded inside the same transaction that applies it, and the tracking
// table insert will serialize on its primary key.
func Up(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("migrate: create tracking table: %w", err)
	}
	ms, err := embedded()
	if err != nil {
		return err
	}
	for _, m := range ms {
		var applied bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version).Scan(&applied); err != nil {
			return fmt.Errorf("migrate: check version %d: %w", m.version, err)
		}
		if applied {
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("migrate: begin %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrate: apply %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrate: record %s: %w", m.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("migrate: commit %s: %w", m.name, err)
		}
	}
	return nil
}

// FromDSN is a convenience for services that connect themselves: it opens a
// connection, runs Up, and closes it again.
func FromDSN(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("migrate: connect: %w", err)
	}
	defer conn.Close(ctx)
	return Up(ctx, conn)
}

type migration struct {
	version int
	name    string
	sql     string
}

func embedded() ([]migration, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: list embedded migrations: %w", err)
	}
	var ms []migration
	for _, e := range entries {
		m := fileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, _ := strconv.Atoi(m[1])
		body, err := migrations.FS.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("migrate: read %s: %w", e.Name(), err)
		}
		ms = append(ms, migration{version: v, name: e.Name(), sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	if len(ms) == 0 {
		return nil, fmt.Errorf("migrate: no migrations embedded")
	}
	return ms, nil
}
