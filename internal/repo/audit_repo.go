package repo

import (
	"context"
	"database/sql"
)

type AuditRepo struct{ DB *sql.DB }

func (r AuditRepo) Write(ctx context.Context, actor, action, object, details string) error {
	_, err := r.DB.ExecContext(ctx, `INSERT INTO audit_log(actor,action,object,details) VALUES(?,?,?,?)`,
		actor, action, object, details)
	return err
}
