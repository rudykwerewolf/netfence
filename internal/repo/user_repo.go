package repo

import (
	"context"
	"database/sql"
	"fmt"
)

type UserRepo struct{ DB *sql.DB }

func (r UserRepo) RoleOf(ctx context.Context, name string) (string, error) {
	var role string
	err := r.DB.QueryRowContext(ctx, `SELECT role FROM users WHERE name=?`, name).Scan(&role)
	if err == sql.ErrNoRows { return "", fmt.Errorf("user %q not found", name) }
	return role, err
}
