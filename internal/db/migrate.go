package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)
//go:embed migrations/*.sql
var fs embed.FS

func CurrentVersion(ctx context.Context, db *sql.DB) (int, error) {
	_, _ = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY)`)
	var v sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v)
	if err != nil { return 0, err }
	//if !v.Valid { return 0, 0 }
        if !v.Valid {
           return 0, nil
        }
	return int(v.Int64), nil
}

func ApplyAll(ctx context.Context, db *sql.DB) error {
	entries, err := fs.ReadDir("migrations")
	if err != nil { return err }
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".sql") && len(name) > 4 {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	cur, err := CurrentVersion(ctx, db)
	if err != nil { return err }
	for _, f := range files {
		prefix := strings.SplitN(f, "_", 2)[0]
		ver, err := strconv.Atoi(prefix)
		if err != nil { return fmt.Errorf("bad migration filename %s", f) }
		if ver <= cur { continue }
		b, err := fs.ReadFile("migrations/" + f)
		if err != nil { return err }
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			return fmt.Errorf("apply %s: %w", f, err)
		}
	}
	return nil
}
