package repo

import (
	"context"
	"database/sql"
	"example.com/netfence/internal/model"
)

type RuleRepo struct{ DB *sql.DB }

func (r RuleRepo) List(ctx context.Context, onlyEnabled bool) ([]model.Rule, error) {
	q := `SELECT id,chain,proto,action,in_if,out_if,comment,enabled FROM rules`
	if onlyEnabled { q += ` WHERE enabled=1` }
	q += ` ORDER BY id`
	rows, err := r.DB.QueryContext(ctx, q)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []model.Rule
	for rows.Next() {
		var m model.Rule
		var inif, outif, comment sql.NullString
		var enabled int
		if err := rows.Scan(&m.ID, &m.Chain, &m.Proto, &m.Action, &inif, &outif, &comment, &enabled); err != nil {
			return nil, err
		}
		if inif.Valid { m.InIf = &inif.String }
		if outif.Valid { m.OutIf = &outif.String }
		if comment.Valid { m.Comment = &comment.String }
		m.Enabled = enabled == 1
		m.Ports, _ = selectInts(r.DB, `SELECT port FROM rule_port WHERE rule_id=?`, m.ID)
		m.SrcCIDRs, _ = selectStrs(r.DB, `SELECT cidr FROM rule_src_cidr WHERE rule_id=?`, m.ID)
		m.DstCIDRs, _ = selectStrs(r.DB, `SELECT cidr FROM rule_dst_cidr WHERE rule_id=?`, m.ID)
		m.ICMPTypes, _ = selectInts(r.DB, `SELECT itype FROM rule_icmp_type WHERE rule_id=?`, m.ID)
		out = append(out, m)
	}
	return out, nil
}

func (r RuleRepo) Create(ctx context.Context, m *model.Rule) (int64, error) {
	tx, err := r.DB.BeginTx(ctx, nil); if err != nil { return 0, err }
	defer func(){ if err!=nil { _=tx.Rollback() } }()
	res, err := tx.ExecContext(ctx, `INSERT INTO rules(chain,proto,action,in_if,out_if,comment,enabled) VALUES(?,?,?,?,?,?,?)`,
		m.Chain, m.Proto, m.Action, nullable(m.InIf), nullable(m.OutIf), nullable(m.Comment), boolToInt(m.Enabled))
	if err != nil { return 0, err }
	id, err := res.LastInsertId(); if err != nil { return 0, err }
	if err = insertInts(tx, `INSERT INTO rule_port(rule_id,port) VALUES(?,?)`, id, m.Ports); err != nil { return 0, err }
	if err = insertStrs(tx, `INSERT INTO rule_src_cidr(rule_id,cidr) VALUES(?,?)`, id, m.SrcCIDRs); err != nil { return 0, err }
	if err = insertStrs(tx, `INSERT INTO rule_dst_cidr(rule_id,cidr) VALUES(?,?)`, id, m.DstCIDRs); err != nil { return 0, err }
	if err = insertInts(tx, `INSERT INTO rule_icmp_type(rule_id,itype) VALUES(?,?)`, id, m.ICMPTypes); err != nil { return 0, err }
	err = tx.Commit(); if err != nil { return 0, err }
	return id, nil
}

func (r RuleRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.DB.ExecContext(ctx, `DELETE FROM rules WHERE id=?`, id)
	return err
}

func selectInts(db *sql.DB, q string, id int64) ([]int, error) {
	rows, err := db.Query(q, id); if err != nil { return nil, err }
	defer rows.Close()
	var out []int; for rows.Next(){ var v int; if err:=rows.Scan(&v); err!=nil { return nil, err }; out=append(out, v) }
	return out, nil
}
func selectStrs(db *sql.DB, q string, id int64) ([]string, error) {
	rows, err := db.Query(q, id); if err != nil { return nil, err }
	defer rows.Close()
	var out []string; for rows.Next(){ var v string; if err:=rows.Scan(&v); err!=nil { return nil, err }; out=append(out, v) }
	return out, nil
}
func insertInts(tx *sql.Tx, q string, id int64, xs []int) error {
	if len(xs)==0 { return nil }
	st, err := tx.Prepare(q); if err!=nil { return err }
	defer st.Close()
	for _, v := range xs { if _, err:=st.Exec(id, v); err!=nil { return err } }
	return nil
}
func insertStrs(tx *sql.Tx, q string, id int64, xs []string) error {
	if len(xs)==0 { return nil }
	st, err := tx.Prepare(q); if err!=nil { return err }
	defer st.Close()
	for _, v := range xs { if _, err:=st.Exec(id, v); err!=nil { return err } }
	return nil
}
func nullable(p *string) any { if p==nil { return nil }; return *p }
func boolToInt(b bool) int { if b { return 1 }; return 0 }
