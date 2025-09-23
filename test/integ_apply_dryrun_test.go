package test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"example.com/netfence/internal/model"
	"example.com/netfence/internal/render"
	"example.com/netfence/internal/repo"
	_ "modernc.org/sqlite"
)

// интеграционный тест рендера правил
func TestDryRunRender(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// создаём минимальные таблицы (как в миграции)
	_, _ = db.Exec(`
	CREATE TABLE defaults(id INTEGER PRIMARY KEY, input_policy TEXT, forward_policy TEXT, output_policy TEXT, log_prefix TEXT);
	INSERT INTO defaults(id,input_policy,forward_policy,output_policy,log_prefix) VALUES(1,'drop','drop','accept','[netfence]');
	CREATE TABLE rules(id INTEGER PRIMARY KEY, chain TEXT, proto TEXT, action TEXT, in_if TEXT, out_if TEXT, comment TEXT, enabled INT);
	CREATE TABLE rule_port(rule_id INT,port INT);
	CREATE TABLE rule_src_cidr(rule_id INT,cidr TEXT);
	CREATE TABLE rule_dst_cidr(rule_id INT,cidr TEXT);
	CREATE TABLE rule_icmp_type(rule_id INT,itype INT);`)

	// добавляем правило через репозиторий
	rr := repo.RuleRepo{DB: db}
	ctx := context.Background()
	r := &model.Rule{Chain: "input", Proto: "tcp", Action: "accept", Ports: []int{22}, Enabled: true}
	id, err := rr.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected id > 0")
	}

	// берём defaults и правила
	d := model.Defaults{InputPolicy: "drop", ForwardPolicy: "drop", OutputPolicy: "accept", LogPrefix: "[netfence]"}
	rules, err := rr.List(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	// рендерим
	s := render.Render(d, rules)

	// проверяем что nft-скрипт содержит нужные куски
	if !strings.Contains(s, "flush ruleset") {
		t.Error("expected flush ruleset")
	}
	if !strings.Contains(s, "th dport { 22 }") {
		t.Error("expected port 22 in render")
	}
	if !strings.Contains(s, "policy drop") {
		t.Error("expected policy drop in render")
	}
	if !strings.Contains(s, "log prefix") {
		t.Error("expected log prefix in render")
	}
}
