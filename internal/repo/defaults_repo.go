package repo

import (
	"context"
	"database/sql"
	"netfence/internal/model"
)

type DefaultsRepo struct{ DB *sql.DB }

func (r DefaultsRepo) Get(ctx context.Context) (model.Defaults, error) {
	var d model.Defaults
	err := r.DB.QueryRowContext(ctx, `SELECT input_policy,forward_policy,output_policy,log_prefix FROM defaults WHERE id=1`).Scan(
		&d.InputPolicy, &d.ForwardPolicy, &d.OutputPolicy, &d.LogPrefix)
	return d, err
}
func (r DefaultsRepo) Set(ctx context.Context, d model.Defaults) error {
	_, err := r.DB.ExecContext(ctx, `UPDATE defaults SET input_policy=?,forward_policy=?,output_policy=?,log_prefix=? WHERE id=1`,
		d.InputPolicy, d.ForwardPolicy, d.OutputPolicy, d.LogPrefix)
	return err
}
