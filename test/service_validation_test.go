package test

import (
	"context"
	"database/sql"
	"testing"
	"example.com/netfence/internal/service"
	"example.com/netfence/internal/repo"
	"example.com/netfence/internal/model"
	_ "modernc.org/sqlite"
)

func TestAddRuleValidation(t *testing.T){
	db, _ := sql.Open("sqlite", "file::memory:?cache=shared")
	_, _ = db.Exec(`CREATE TABLE rules(id INTEGER PRIMARY KEY,chain TEXT,proto TEXT,action TEXT,in_if TEXT,out_if TEXT,comment TEXT,enabled INT,created_at TEXT,updated_at TEXT);
CREATE TABLE rule_port(rule_id INT,port INT,PRIMARY KEY(rule_id,port));
CREATE TABLE rule_src_cidr(rule_id INT,cidr TEXT,PRIMARY KEY(rule_id,cidr));
CREATE TABLE rule_dst_cidr(rule_id INT,cidr TEXT,PRIMARY KEY(rule_id,cidr));
CREATE TABLE rule_icmp_type(rule_id INT,itype INT,PRIMARY KEY(rule_id,itype));`)
	svc := service.RulesService{Repo: repo.RuleRepo{DB: db}}
	_, err := svc.Add(context.Background(),"tester",&model.Rule{Chain:"bad",Proto:"tcp",Action:"accept",Enabled:true})
	if err == nil { t.Fatal("expected error") }
}
