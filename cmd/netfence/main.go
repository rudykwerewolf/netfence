package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	dbpkg "netfence/internal/db"
	"netfence/internal/model"
	"netfence/internal/render"
	"netfence/internal/repo"
	"netfence/internal/service"
	"netfence/internal/tui"
	"netfence/internal/util"

	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

const (
	defaultDB = "/etc/firewall.db"
	lockFile  = "/var/lock/netfence.lock"
)

func openDB(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?cache=shared&_busy_timeout=5000")
}

// ensureDB: создаёт файл БД (если нет), каталоги, миграции, дефолтных пользователей.
func ensureDB(path string) error {
	// ":memory:" и явные DSN-строки не трогаем файлово
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		db, err := openDB(path)
		if err != nil {
			return err
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := dbpkg.ApplyAll(ctx, db); err != nil {
			return err
		}
		// users bootstrap
		if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, role TEXT)`); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO users(name, role) VALUES('root','admin'),('operator','operator')`); err != nil {
			return err
		}
		return nil
	}

	// Файловая БД
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("create db file: %w", err)
		}
		_ = f.Close()
	} else if err != nil {
		return fmt.Errorf("stat db: %w", err)
	}

	db, err := openDB(path)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dbpkg.ApplyAll(ctx, db); err != nil {
		return err
	}
	// bootstrap users (на случай, если миграции этого не делают)
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, role TEXT)`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO users(name, role) VALUES('root','admin'),('operator','operator')`); err != nil {
		return err
	}
	return nil
}

func main() {
	dbPath := defaultDB
	actor := "root"

	root := &cobra.Command{
		Use:   "netfence",
		Short: "netfence - firewall/NFT manager with SQLite and TUI",
	}

	root.PersistentFlags().StringVar(&dbPath, "db", defaultDB, "path to firewall sqlite db")
	root.PersistentFlags().StringVar(&actor, "as", "root", "actor (RBAC user)")

	// --- list ---
	var onlyEnabled bool
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List firewall rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}
			rs, err := repo.RuleRepo{DB: conn}.List(ctx, onlyEnabled)
			if err != nil {
				return err
			}
			printRulesTable(rs)
			return nil
		},
	}
	listCmd.Flags().BoolVar(&onlyEnabled, "enabled", false, "show only enabled rules")

	// --- defaults (show) ---
	defGet := &cobra.Command{
		Use:   "defaults",
		Short: "Show default policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}
			def, err := repo.DefaultsRepo{DB: conn}.Get(ctx)
			if err != nil {
				return err
			}
			printDefaultsTable(def)
			return nil
		},
	}

	// --- set-defaults ---
	var inpol, fwdpol, outpol, logpref string
	defSet := &cobra.Command{
		Use:   "set-defaults",
		Short: "Set default policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			lock, err := util.Acquire(lockFile)
			if err != nil {
				return err
			}
			defer lock.Release()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}

			role, err := repo.UserRepo{DB: conn}.RoleOf(ctx, actor)
			if err != nil {
				return err
			}
			if role != "admin" {
				return fmt.Errorf("rbac: need admin, got %s", role)
			}

			ds := service.DefaultsService{Repo: repo.DefaultsRepo{DB: conn}}
			if err := ds.Set(ctx, model.Defaults{
				InputPolicy:   inpol,
				ForwardPolicy: fwdpol,
				OutputPolicy:  outpol,
				LogPrefix:     logpref,
			}); err != nil {
				return err
			}

			_ = service.AuditService{Repo: repo.AuditRepo{DB: conn}}.Log(ctx, actor, "set_defaults", "defaults:1",
				map[string]string{"input": inpol, "forward": fwdpol, "output": outpol, "log": logpref})
			fmt.Println("ok")
			return nil
		},
	}
	defSet.Flags().StringVar(&inpol, "input", "drop", "policy for input (accept|drop)")
	defSet.Flags().StringVar(&fwdpol, "forward", "drop", "policy for forward (accept|drop)")
	defSet.Flags().StringVar(&outpol, "output", "accept", "policy for output (accept|drop)")
	defSet.Flags().StringVar(&logpref, "log-prefix", "", "log prefix or empty")

	// --- add-rule ---
	var chain, proto, action, inif, outif, ports, srcs, dsts, comment string
	var enabled bool
	add := &cobra.Command{
		Use:   "add-rule",
		Short: "Create a rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			lock, err := util.Acquire(lockFile)
			if err != nil {
				return err
			}
			defer lock.Release()

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}

			role, err := repo.UserRepo{DB: conn}.RoleOf(ctx, actor)
			if err != nil {
				return err
			}
			if role != "admin" && role != "operator" {
				return fmt.Errorf("rbac: need operator or admin, got %s", role)
			}

			var prts []int
			if ports != "" {
				for _, p := range strings.Split(ports, ",") {
					var v int
					if _, e := fmt.Sscan(strings.TrimSpace(p), &v); e != nil {
						return e
					}
					prts = append(prts, v)
				}
			}
			r := &model.Rule{
				Chain:    chain, Proto: proto, Action: action,
				Ports:    prts, Enabled: enabled,
				SrcCIDRs: splitCSV(srcs), DstCIDRs: splitCSV(dsts),
			}
			if inif != "" {
				r.InIf = &inif
			}
			if outif != "" {
				r.OutIf = &outif
			}
			if comment != "" {
				r.Comment = &comment
			}

			rr := repo.RuleRepo{DB: conn}
			as := service.AuditService{Repo: repo.AuditRepo{DB: conn}}
			svc := service.RulesService{Repo: rr, Audit: as}
			id, err := svc.Add(ctx, actor, r)
			if err != nil {
				return err
			}
			fmt.Printf("created id=%d\n", id)
			return nil
		},
	}
	add.Flags().StringVar(&chain, "chain", "input", "input|forward|output")
	add.Flags().StringVar(&proto, "proto", "all", "all|tcp|udp|icmp")
	add.Flags().StringVar(&action, "action", "accept", "accept|drop")
	add.Flags().StringVar(&inif, "in-if", "", "incoming interface")
	add.Flags().StringVar(&outif, "out-if", "", "outgoing interface")
	add.Flags().StringVar(&ports, "ports", "", "csv ports e.g. 22,80,443")
	add.Flags().StringVar(&srcs, "src", "", "csv src CIDRs")
	add.Flags().StringVar(&dsts, "dst", "", "csv dst CIDRs")
	add.Flags().StringVar(&comment, "comment", "", "comment")
	add.Flags().BoolVar(&enabled, "enabled", true, "enabled")

	// --- del-rule ---
	del := &cobra.Command{
		Use:   "del-rule <id>",
		Short: "Delete rule by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			lock, err := util.Acquire(lockFile)
			if err != nil {
				return err
			}
			defer lock.Release()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}

			role, err := repo.UserRepo{DB: conn}.RoleOf(ctx, actor)
			if err != nil {
				return err
			}
			if role != "admin" && role != "operator" {
				return fmt.Errorf("rbac: need operator or admin, got %s", role)
			}

			var id int64
			_, _ = fmt.Sscan(args[0], &id)
			svc := service.RulesService{Repo: repo.RuleRepo{DB: conn}, Audit: service.AuditService{Repo: repo.AuditRepo{DB: conn}}}
			return svc.Delete(ctx, actor, id)
		},
	}

	// --- export/import YAML ---
	var path string
	export := &cobra.Command{
		Use:   "export",
		Short: "Export snapshot to YAML",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}

			def, _ := repo.DefaultsRepo{DB: conn}.Get(ctx)
			rules, _ := repo.RuleRepo{DB: conn}.List(ctx, false)
			snap := struct {
				Defaults model.Defaults `yaml:"defaults"`
				Rules    []model.Rule   `yaml:"rules"`
			}{def, rules}
			return util.WriteYAML(path, snap)
		},
	}
	export.Flags().StringVar(&path, "file", "netfence.yaml", "output yaml file")

	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import snapshot from YAML",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			lock, err := util.Acquire(lockFile)
			if err != nil {
				return err
			}
			defer lock.Release()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}

			role, err := repo.UserRepo{DB: conn}.RoleOf(ctx, actor)
			if err != nil {
				return err
			}
			if role != "admin" {
				return fmt.Errorf("rbac: need admin")
			}

			var snap struct {
				Defaults model.Defaults `yaml:"defaults"`
				Rules    []model.Rule   `yaml:"rules"`
			}
			if err := util.ReadYAML(path, &snap); err != nil {
				return err
			}

			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM rules`); err != nil {
				_ = tx.Rollback()
				return err
			}
			if _, err := tx.Exec(`UPDATE defaults SET input_policy=?,forward_policy=?,output_policy=?,log_prefix=? WHERE id=1`,
				snap.Defaults.InputPolicy, snap.Defaults.ForwardPolicy, snap.Defaults.OutputPolicy, snap.Defaults.LogPrefix); err != nil {
				_ = tx.Rollback()
				return err
			}
			rr := repo.RuleRepo{DB: conn}
			for i := range snap.Rules {
				if _, err := rr.Create(ctx, &snap.Rules[i]); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			_ = service.AuditService{Repo: repo.AuditRepo{DB: conn}}.Log(ctx, actor, "import_yaml", "snapshot", map[string]any{"count": len(snap.Rules)})
			fmt.Println("imported")
			return nil
		},
	}
	importCmd.Flags().StringVar(&path, "file", "netfence.yaml", "input yaml file")

	// --- dryrun (табличный превью) ---
	dryrun := &cobra.Command{
		Use:   "dryrun",
		Short: "Preview ruleset (tables)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}

			def, _ := repo.DefaultsRepo{DB: conn}.Get(ctx)
			rules, _ := repo.RuleRepo{DB: conn}.List(ctx, true)
			printDefaultsTable(def)
			fmt.Println()
			printRulesTable(rules)
			return nil
		},
	}

	// --- apply ---
	apply := &cobra.Command{
		Use:   "apply",
		Short: "Apply rules to nftables",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			lock, err := util.Acquire(lockFile)
			if err != nil {
				return err
			}
			defer lock.Release()

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := openDB(dbPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := dbpkg.ApplyAll(ctx, conn); err != nil {
				return err
			}

			role, err := repo.UserRepo{DB: conn}.RoleOf(ctx, actor)
			if err != nil {
				return err
			}
			if role != "admin" && role != "operator" {
				return fmt.Errorf("rbac: need operator or admin, got %s", role)
			}

			def, _ := repo.DefaultsRepo{DB: conn}.Get(ctx)
			rules, _ := repo.RuleRepo{DB: conn}.List(ctx, true)
			script := render.Render(def, rules)
			_, stderr, err := (util.ShellRunner{}).Run("nft", []byte(script), "-f", "-")
			if err != nil {
				return fmt.Errorf("nft failed: %v\n%s", err, stderr)
			}
			_ = service.AuditService{Repo: repo.AuditRepo{DB: conn}}.Log(ctx, actor, "apply", "ruleset", map[string]int{"rules": len(rules)})
			fmt.Println("applied")
			return nil
		},
	}

	// --- tui ---
	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureDB(dbPath); err != nil {
				return err
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			return tui.Run(ctx, dbPath, actor)
		},
	}

	root.AddCommand(listCmd, defGet, defSet, add, del, export, importCmd, dryrun, apply, tuiCmd)

	// Без аргументов — сразу TUI
	if len(os.Args) == 1 {
		if err := ensureDB(dbPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := tui.Run(ctx, dbPath, actor); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------- pretty printers ----------

func printRulesTable(rs []model.Rule) {
	fmt.Println("ID  CHAIN    PROTO  ACTION  EN  IN_IF     OUT_IF    PORTS        SRC               DST               ICMP     COMMENT")
	for _, x := range rs {
		inIf, outIf, comment := "-", "-", "-"
		if x.InIf != nil && *x.InIf != "" {
			inIf = *x.InIf
		}
		if x.OutIf != nil && *x.OutIf != "" {
			outIf = *x.OutIf
		}
		if x.Comment != nil && *x.Comment != "" {
			comment = *x.Comment
		}
		en := "-"
		if x.Enabled {
			en = "✓"
		}
		fmt.Printf("%-3d %-8s %-6s %-7s %-3s %-9s %-9s %-12s %-16s %-16s %-8s %-s\n",
			x.ID, x.Chain, x.Proto, x.Action, en,
			inIf, outIf,
			intSlice(x.Ports), strSlice(x.SrcCIDRs), strSlice(x.DstCIDRs),
			intSlice(x.ICMPTypes), comment)
	}
}

func printDefaultsTable(def model.Defaults) {
	fmt.Println("DEFAULT POLICIES")
	fmt.Printf("%-8s %-8s %-8s %-s\n", "INPUT", "FORWARD", "OUTPUT", "LOG_PREFIX")
	fmt.Printf("%-8s %-8s %-8s %-s\n", def.InputPolicy, def.ForwardPolicy, def.OutputPolicy, def.LogPrefix)
}

// helpers for pretty printers
func intSlice(v []int) string {
	if len(v) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, x := range v {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprint(x))
	}
	sb.WriteByte(']')
	return sb.String()
}
func strSlice(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	return "[" + strings.Join(v, ",") + "]"
}
