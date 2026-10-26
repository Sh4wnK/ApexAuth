// Package migrations embeds the SQL migration files so they ship inside the
// binary. The internal/migrate package applies them against PostgreSQL.
package migrations

import "embed"

// FS holds all migration files (NNNN_name.up.sql).
//
//go:embed *.up.sql
var FS embed.FS
