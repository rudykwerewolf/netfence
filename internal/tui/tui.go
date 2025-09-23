package tui

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"netfence/internal/model"
	"netfence/internal/render"
	"netfence/internal/repo"
	"netfence/internal/service"
	"netfence/internal/util"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	_ "modernc.org/sqlite"
)

const lockFile = "/var/lock/netfence.lock"

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213"))
	tabActive    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
	tabInactive  = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("36")).Bold(true)
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	okStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	itemStyle    = lipgloss.NewStyle().PaddingLeft(2)
	itemSelStyle = lipgloss.NewStyle().PaddingLeft(0).Bold(true).Foreground(lipgloss.Color("219")).Background(lipgloss.Color("60")).Padding(0, 1)
	btnStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	btnSelStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("219")).Background(lipgloss.Color("60")).Padding(0, 1)
	fieldTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
)

type screen int

const (
	scrMain screen = iota
	scrRules
	scrDefaults
	scrPreview
	scrAddRule
)

type modelT struct {
	ctx    context.Context
	dbPath string
	actor  string
	db     *sql.DB

	width, height int
	errMsg, okMsg string

	scr screen

	// Main
	mainItems  []string
	mainCursor int

	// Rules
	rulesTbl  table.Model
	bottomIdx int

	// Defaults
	policies       model.Defaults
	logInput       textinput.Model
	defocus        int // 0..2 policies, 3 log prefix
	defBtns        []string
	defBtnIx       int
	defocusSection string // "fields" | "buttons"

	// Preview
	preview      viewport.Model
	previewBtns  []string
	previewBtnIx int

	// Add rule
	addInputs []*textinput.Model
	addStep   int
	addFocus  string // "fields" | "buttons"
	addBtnIx  int

	quit bool
}

// ---------- DB/setup ----------

func openDB(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?cache=shared&_busy_timeout=5000")
}

func dbApplyAll(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}
	_, _ = db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS defaults(id INTEGER PRIMARY KEY, input_policy TEXT, forward_policy TEXT, output_policy TEXT, log_prefix TEXT);
INSERT OR IGNORE INTO defaults(id,input_policy,forward_policy,output_policy,log_prefix) VALUES(1,'drop','drop','accept','');
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, chain TEXT, proto TEXT, action TEXT, in_if TEXT, out_if TEXT, comment TEXT, enabled INT);
CREATE TABLE IF NOT EXISTS rule_port(rule_id INT, port INT);
CREATE TABLE IF NOT EXISTS rule_src_cidr(rule_id INT, cidr TEXT);
CREATE TABLE IF NOT EXISTS rule_dst_cidr(rule_id INT, cidr TEXT);
CREATE TABLE IF NOT EXISTS rule_icmp_type(rule_id INT, itype INT);
`)
	return nil
}

func New(ctx context.Context, dbPath, actor string) (*modelT, error) {
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	m := &modelT{
		ctx:    ctx,
		dbPath: dbPath,
		actor:  actor,
		db:     db,
		scr:    scrMain,
	}
	m.initMain()
	m.initRulesTable()
	m.initDefaults()
	if err := m.reloadAll(); err != nil {
		m.errMsg = err.Error()
	}
	return m, nil
}

func (m *modelT) Close() { _ = m.db.Close() }

func (m *modelT) initMain() {
	m.mainItems = []string{"Manage Rules", "Set Default Policies", "Preview & Apply", "Quit"}
	m.mainCursor = 0
}

func (m *modelT) initRulesTable() {
	cols := []table.Column{
		{Title: "ID", Width: 4}, {Title: "CHAIN", Width: 8}, {Title: "PROTO", Width: 6}, {Title: "ACTION", Width: 7},
		{Title: "EN", Width: 3}, {Title: "IN_IF", Width: 9}, {Title: "OUT_IF", Width: 9}, {Title: "PORTS", Width: 12},
		{Title: "SRC", Width: 16}, {Title: "DST", Width: 16}, {Title: "ICMP", Width: 8}, {Title: "COMMENT", Width: 18},
	}
	t := table.New(table.WithColumns(cols), table.WithFocused(true), table.WithHeight(12))
	m.rulesTbl = t
	m.bottomIdx = 0
}

func (m *modelT) initDefaults() {
	m.defocus = 0
	m.defBtns = []string{"[Save]"} // только Save
	m.defBtnIx = 0
	m.defocusSection = "fields"

	m.logInput = textinput.New()
	m.logInput.Placeholder = "LOG_PREFIX (optional)"
	m.logInput.CharLimit = 60
}

func (m *modelT) reloadAll() error {
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()
	if err := dbApplyAll(ctx, m.db); err != nil {
		return err
	}

	def, err := repo.DefaultsRepo{DB: m.db}.Get(ctx)
	if err != nil {
		return err
	}
	m.policies = def
	m.logInput.SetValue(def.LogPrefix)

	rs, err := repo.RuleRepo{DB: m.db}.List(ctx, false)
	if err != nil {
		return err
	}
	rows := make([]table.Row, 0, len(rs))
	for _, r := range rs {
		rows = append(rows, table.Row{
			fmt.Sprint(r.ID), r.Chain, r.Proto, r.Action,
			boolFlag(r.Enabled), ptrOrDash(r.InIf), ptrOrDash(r.OutIf),
			intSlice(r.Ports), strSlice(r.SrcCIDRs), strSlice(r.DstCIDRs),
			intSlice(r.ICMPTypes), ptrOrDash(r.Comment),
		})
	}
	m.rulesTbl.SetRows(rows)
	return nil
}

func boolFlag(b bool) string {
	if b {
		return "✓"
	}
	return "-"
}
func ptrOrDash(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}
func intSlice(v []int) string {
	if len(v) == 0 {
		return "-"
	}
	var sb strings.Builder
	for i, x := range v {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprint(x))
	}
	return sb.String()
}
func strSlice(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return "[" + strings.Join(v, ",") + "]"
}

// ---------- Bubble Tea ----------

func (m *modelT) Init() tea.Cmd { return nil }

func (m *modelT) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.preview = viewport.Model{Width: m.width - 4, Height: m.height - 12}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "f10":
			m.quit = true
			return m, tea.Quit
		case "esc":
			switch m.scr {
			case scrMain:
				m.quit = true
				return m, tea.Quit
			default:
				m.scr = scrMain
				return m, nil
			}
		}

		switch m.scr {
		case scrMain:
			return m.updateMain(msg)
		case scrRules:
			return m.updateRules(msg)
		case scrDefaults:
			return m.updateDefaults(msg)
		case scrPreview:
			return m.updatePreview(msg)
		case scrAddRule:
			return m.updateAddRule(msg)
		}
	}
	return m, nil
}

// --- main ---

func (m *modelT) updateMain(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.mainCursor > 0 {
			m.mainCursor--
		}
	case "down", "j":
		if m.mainCursor < len(m.mainItems)-1 {
			m.mainCursor++
		}
	case "enter":
		switch m.mainCursor {
		case 0:
			m.scr = scrRules
		case 1:
			m.scr = scrDefaults
		case 2:
			if err := m.preparePreviewTables(); err != nil {
				m.errMsg = err.Error()
			} else {
				m.scr = scrPreview
			}
		case 3:
			m.quit = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// --- rules ---

func (m *modelT) updateRules(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab":
		m.bottomIdx = (m.bottomIdx + 1) % len(m.rulesButtons())
	case "left":
		if m.bottomIdx > 0 {
			m.bottomIdx--
		}
	case "right":
		if m.bottomIdx < len(m.rulesButtons())-1 {
			m.bottomIdx++
		}
	case "enter":
		return m.execRulesButton()
	case "r":
		m.errMsg, m.okMsg = "", ""
		if err := m.reloadAll(); err != nil {
			m.errMsg = err.Error()
		} else {
			m.okMsg = "reloaded"
		}
	}
	var cmd tea.Cmd
	m.rulesTbl, cmd = m.rulesTbl.Update(msg)
	return m, cmd
}

func (m *modelT) rulesButtons() []string {
	return []string{"[Add]", "[Delete]", "[Reload]", "[Back]"}
}

func (m *modelT) execRulesButton() (tea.Model, tea.Cmd) {
	switch m.bottomIdx {
	case 0:
		m.startAddRuleWizard()
		m.scr = scrAddRule
	case 1:
		if err := m.deleteSelected(); err != nil {
			m.errMsg = err.Error()
		} else {
			m.okMsg = "deleted"
			_ = m.reloadAll()
		}
	case 2:
		m.errMsg, m.okMsg = "", ""
		if err := m.reloadAll(); err != nil {
			m.errMsg = err.Error()
		} else {
			m.okMsg = "reloaded"
		}
	case 3:
		m.scr = scrMain
	}
	return m, nil
}

// --- defaults ---

func (m *modelT) updateDefaults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.defocusSection == "buttons" {
			m.defocusSection = "fields"
			m.defocus = 3
			m.logInput.Focus()
			return m, nil
		}
		if m.defocus > 0 {
			m.defocus--
		}
	case "down", "j":
		if m.defocusSection == "buttons" {
			return m, nil
		}
		if m.defocus < 3 {
			m.defocus++
		}
		if m.defocus == 3 {
			m.logInput.Focus()
		} else {
			m.logInput.Blur()
		}
	case "left", "right", " ":
		if m.defocusSection == "buttons" {
			// одна кнопка — индекс всегда 0
		} else if m.defocus >= 0 && m.defocus <= 2 {
			switch m.defocus {
			case 0:
				m.policies.InputPolicy = togglePolicy(m.policies.InputPolicy)
			case 1:
				m.policies.ForwardPolicy = togglePolicy(m.policies.ForwardPolicy)
			case 2:
				m.policies.OutputPolicy = togglePolicy(m.policies.OutputPolicy)
			}
		}
	case "tab":
		if m.defocusSection == "fields" {
			m.defocusSection = "buttons"
			m.logInput.Blur()
			m.defBtnIx = 0
		} else {
			m.defBtnIx = 0
		}
	case "lefttab": // Shift+Tab
		if m.defocusSection == "buttons" {
			m.defocusSection = "fields"
			if m.defocus == 3 {
				m.logInput.Focus()
			}
		}
	case "enter":
		if m.defocusSection == "buttons" {
			return m.execDefaultsButton() // только Save
		}
	case "esc":
		m.scr = scrMain
		return m, nil
	}

	if m.defocus == 3 && m.defocusSection == "fields" {
		if !m.logInput.Focused() {
			m.logInput.Focus()
		}
	} else {
		if m.logInput.Focused() {
			m.logInput.Blur()
		}
	}
	var cmd tea.Cmd
	m.logInput, cmd = m.logInput.Update(msg)
	return m, cmd
}

func (m *modelT) execDefaultsButton() (tea.Model, tea.Cmd) {
	// Save → сохранить и вернуться в главное меню
	m.policies.LogPrefix = m.logInput.Value()
	if err := m.saveDefaults(); err != nil {
		m.errMsg = err.Error()
	} else {
		m.okMsg = "defaults saved"
		m.scr = scrMain
	}
	return m, nil
}

// --- preview ---

func (m *modelT) updatePreview(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab":
		m.previewBtnIx = (m.previewBtnIx + 1) % len(m.previewBtns)
	case "left":
		if m.previewBtnIx > 0 {
			m.previewBtnIx--
		}
	case "right":
		if m.previewBtnIx < len(m.previewBtns)-1 {
			m.previewBtnIx++
		}
	case "enter":
		if m.previewBtnIx == 0 { // Apply
			if err := m.apply(); err != nil {
				m.errMsg = err.Error()
			} else {
				m.okMsg = "applied"
				m.scr = scrMain // ← возврат в меню после успешного apply
			}
		} else { // Back
			m.scr = scrMain
		}
	case "esc", "q":
		m.scr = scrMain
	}
	return m, nil
}

func (m *modelT) preparePreviewTables() error {
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()
	def, _ := repo.DefaultsRepo{DB: m.db}.Get(ctx)
	rules, _ := repo.RuleRepo{DB: m.db}.List(ctx, true)
	content := buildPreviewTables(def, rules)
	m.preview = viewport.Model{Width: m.width - 4, Height: m.height - 12}
	m.preview.SetContent(content)
	m.previewBtns = []string{"[Apply]", "[Back]"}
	m.previewBtnIx = 0
	return nil
}

// --- add rule ---

func (m *modelT) startAddRuleWizard() {
	labels := []string{
		"chain(input/forward/output)",
		"proto(all/tcp/udp/icmp)",
		"action(accept/drop)",
		"in-if(Optional)",
		"out-if(Optional)",
		"ports(csv)",
		"src(csv CIDR)",
		"dst(csv CIDR)",
		"comment(Optional)",
	}
	m.addInputs = make([]*textinput.Model, len(labels))
	for i, lab := range labels {
		ti := textinput.New()
		ti.Placeholder = lab
		if i == 0 {
			ti.SetValue("input")
		}
		if i == 1 {
			ti.SetValue("all")
		}
		if i == 2 {
			ti.SetValue("accept")
		}
		m.addInputs[i] = &ti
	}
	m.addStep = 0
	m.addFocus = "fields"
	m.addBtnIx = 0
	for i := range m.addInputs {
		if i == 0 {
			m.addInputs[i].Focus()
		} else {
			m.addInputs[i].Blur()
		}
	}
}

func (m *modelT) updateAddRule(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.addFocus == "fields" && m.addStep > 0 {
			m.addStep--
			for i := range m.addInputs {
				if i == m.addStep {
					m.addInputs[i].Focus()
				} else {
					m.addInputs[i].Blur()
				}
			}
		}
	case "down", "j":
		if m.addFocus == "fields" {
			if m.addStep < len(m.addInputs)-1 {
				m.addStep++
				for i := range m.addInputs {
					if i == m.addStep {
						m.addInputs[i].Focus()
					} else {
						m.addInputs[i].Blur()
					}
				}
			} else {
				m.addFocus = "buttons"
				m.addBtnIx = 0
				m.addInputs[m.addStep].Blur()
			}
		}
	case "lefttab": // Shift+Tab
		if m.addFocus == "buttons" {
			m.addFocus = "fields"
			m.addStep = len(m.addInputs) - 1
			m.addInputs[m.addStep].Focus()
		} else if m.addStep > 0 {
			m.addStep--
			for i := range m.addInputs {
				if i == m.addStep {
					m.addInputs[i].Focus()
				} else {
					m.addInputs[i].Blur()
				}
			}
		}
	case "tab":
		if m.addFocus == "fields" {
			if m.addStep < len(m.addInputs)-1 {
				m.addStep++
				for i := range m.addInputs {
					if i == m.addStep {
						m.addInputs[i].Focus()
					} else {
						m.addInputs[i].Blur()
					}
				}
			} else {
				m.addFocus = "buttons"
				m.addBtnIx = 0
				m.addInputs[m.addStep].Blur()
			}
		} else {
			m.addBtnIx = (m.addBtnIx + 1) % 2
		}
	case "left":
		if m.addFocus == "buttons" && m.addBtnIx > 0 {
			m.addBtnIx--
		}
	case "right":
		if m.addFocus == "buttons" && m.addBtnIx < 1 {
			m.addBtnIx++
		}
	case "enter":
		if m.addFocus == "fields" {
			if m.addStep < len(m.addInputs)-1 {
				m.addStep++
				for i := range m.addInputs {
					if i == m.addStep {
						m.addInputs[i].Focus()
					} else {
						m.addInputs[i].Blur()
					}
				}
			} else {
				m.addFocus = "buttons"
				m.addBtnIx = 0
				m.addInputs[m.addStep].Blur()
			}
		} else {
			if m.addBtnIx == 0 { // Save
				if err := m.saveNewRule(); err != nil {
					m.errMsg = err.Error()
				} else {
					m.okMsg = "rule added"
					_ = m.reloadAll()
					m.scr = scrRules
				}
			} else { // Cancel
				m.scr = scrRules
			}
		}
	case "esc":
		m.scr = scrRules
		return m, nil
	}

	if m.addFocus == "fields" && m.addStep >= 0 && m.addStep < len(m.addInputs) {
		var cmd tea.Cmd
		*m.addInputs[m.addStep], cmd = m.addInputs[m.addStep].Update(msg)
		return m, cmd
	}
	return m, nil
}

// ---------- VIEW ----------

func (m *modelT) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("NetFence"))
	b.WriteString("   ")
	b.WriteString(tab(scrMain, m.scr, "Main"))
	b.WriteString(tab(scrRules, m.scr, "Rules"))
	b.WriteString(tab(scrDefaults, m.scr, "Defaults"))
	b.WriteString(tab(scrPreview, m.scr, "Preview"))
	b.WriteString("\n")

	if m.errMsg != "" {
		b.WriteString(errStyle.Render("ERROR: " + m.errMsg))
		b.WriteString("\n")
	}
	if m.okMsg != "" {
		b.WriteString(okStyle.Render(m.okMsg))
		b.WriteString("\n")
	}

	switch m.scr {
	case scrMain:
		b.WriteString(headerStyle.Render("Select an action:") + "\n\n")
		for i, it := range m.mainItems {
			if i == m.mainCursor {
				b.WriteString(itemSelStyle.Render("► " + it))
			} else {
				b.WriteString(itemStyle.Render("  " + it))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n" + btnRow([]string{"[Enter] OK", "[ESC/F10] Quit"}, -1))

	case scrRules:
		b.WriteString(headerStyle.Render("Rules") + "\n")
		b.WriteString(m.rulesTbl.View() + "\n\n")
		b.WriteString(btnRow(m.rulesButtons(), m.bottomIdx))

	case scrDefaults:
		b.WriteString(headerStyle.Render("Default Policies") + "\n\n")
		b.WriteString(renderDefaultLine("INPUT   ", m.policies.InputPolicy, m.defocus == 0 && m.defocusSection == "fields"))
		b.WriteString(renderDefaultLine("FORWARD ", m.policies.ForwardPolicy, m.defocus == 1 && m.defocusSection == "fields"))
		b.WriteString(renderDefaultLine("OUTPUT  ", m.policies.OutputPolicy, m.defocus == 2 && m.defocusSection == "fields"))
		b.WriteString("\n" + fieldTitle.Render("LOG_PREFIX") + "\n")
		b.WriteString(m.logInput.View() + "\n\n")
		sel := -1
		if m.defocusSection == "buttons" {
			sel = m.defBtnIx
		}
		b.WriteString(btnRow(m.defBtns, sel))

	case scrPreview:
		b.WriteString(headerStyle.Render("Preview (tables)") + "\n")
		if m.preview.Width == 0 {
			m.preview = viewport.Model{Width: 80, Height: 20}
		}
		b.WriteString(m.preview.View() + "\n\n")
		b.WriteString(btnRow(m.previewBtns, m.previewBtnIx))

	case scrAddRule:
		b.WriteString(headerStyle.Render("Add Rule") + "\n\n")
		for i, in := range m.addInputs {
			prefix := "  "
			if m.addFocus == "fields" && i == m.addStep {
				prefix = "> "
			}
			b.WriteString(prefix + in.View() + "\n")
		}
		sel := -1
		if m.addFocus == "buttons" {
			sel = m.addBtnIx
		}
		b.WriteString("\n" + btnRow([]string{"[Save]", "[Cancel]"}, sel))
	}

	b.WriteString("\n")
	return b.String()
}

func tab(tv screen, cur screen, label string) string {
	if tv == cur {
		return tabActive.Render(label)
	}
	return tabInactive.Render(label)
}

func btnRow(btns []string, sel int) string {
	var parts []string
	for i, s := range btns {
		if i == sel {
			parts = append(parts, btnSelStyle.Render(s))
		} else {
			parts = append(parts, btnStyle.Render(s))
		}
	}
	return strings.Join(parts, " ")
}

func renderDefaultLine(name, val string, focused bool) string {
	r1 := "( ) ACCEPT"
	r2 := "( ) DROP"
	if strings.EqualFold(val, "accept") {
		r1 = "(*) ACCEPT"
	} else {
		r2 = "(*) DROP"
	}
	line := fmt.Sprintf("%-8s %s    %s", name, r1, r2)
	if focused {
		return itemSelStyle.Render(line) + "\n"
	}
	return itemStyle.Render(line) + "\n"
}

// ---------- preview tables ----------

func buildPreviewTables(def model.Defaults, rules []model.Rule) string {
	var b strings.Builder
	b.WriteString("DEFAULT POLICIES\n")
	b.WriteString(fmt.Sprintf("%-8s %-8s %-8s %-s\n", "INPUT", "FORWARD", "OUTPUT", "LOG_PREFIX"))
	b.WriteString(fmt.Sprintf("%-8s %-8s %-8s %-s\n\n", def.InputPolicy, def.ForwardPolicy, def.OutputPolicy, def.LogPrefix))

	b.WriteString("RULES\n")
	b.WriteString(fmt.Sprintf("%-4s %-8s %-6s %-7s %-2s %-9s %-9s %-12s %-16s %-16s %-8s %-18s\n",
		"ID", "CHAIN", "PROTO", "ACTION", "EN", "IN_IF", "OUT_IF", "PORTS", "SRC", "DST", "ICMP", "COMMENT"))

	if len(rules) == 0 {
		b.WriteString("(no enabled rules)\n")
		return b.String()
	}
	for _, x := range rules {
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
		ports := intSlice(x.Ports)
		src := strSlice(x.SrcCIDRs)
		dst := strSlice(x.DstCIDRs)
		icmp := intSlice(x.ICMPTypes)
		en := "-"
		if x.Enabled {
			en = "✓"
		}
		b.WriteString(fmt.Sprintf("%-4d %-8s %-6s %-7s %-2s %-9s %-9s %-12s %-16s %-16s %-8s %-18s\n",
			x.ID, x.Chain, x.Proto, x.Action, en, inIf, outIf, ports, src, dst, icmp, comment))
	}
	return b.String()
}

// ---------- actions ----------

func (m *modelT) apply() error {
	lock, err := util.Acquire(lockFile)
	if err != nil {
		return err
	}
	defer lock.Release()
	ctx, cancel := context.WithTimeout(m.ctx, 8*time.Second)
	defer cancel()
	role, err := repo.UserRepo{DB: m.db}.RoleOf(ctx, m.actor)
	if err != nil {
		return err
	}
	if role != "admin" && role != "operator" {
		return fmt.Errorf("rbac: need operator or admin, got %s", role)
	}
	def, _ := repo.DefaultsRepo{DB: m.db}.Get(ctx)
	rules, _ := repo.RuleRepo{DB: m.db}.List(ctx, true)
	script := render.Render(def, rules)
	_, stderr, err := (util.ShellRunner{}).Run("nft", []byte(script), "-f", "-")
	if err != nil {
		return fmt.Errorf("nft failed: %v\n%s", err, stderr)
	}
	_ = service.AuditService{Repo: repo.AuditRepo{DB: m.db}}.Log(ctx, m.actor, "apply", "ruleset", map[string]int{"rules": len(rules)})
	return nil
}

func (m *modelT) deleteSelected() error {
	row := m.rulesTbl.Cursor()
	rows := m.rulesTbl.Rows()
	if row < 0 || row >= len(rows) {
		return nil
	}
	idStr := rows[row][0]
	var id int64
	_, _ = fmt.Sscan(idStr, &id)

	lock, err := util.Acquire(lockFile)
	if err != nil {
		return err
	}
	defer lock.Release()

	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()
	role, err := repo.UserRepo{DB: m.db}.RoleOf(ctx, m.actor)
	if err != nil {
		return err
	}
	if role != "admin" && role != "operator" {
		return fmt.Errorf("rbac: need operator or admin, got %s", role)
	}
	svc := service.RulesService{Repo: repo.RuleRepo{DB: m.db}, Audit: service.AuditService{Repo: repo.AuditRepo{DB: m.db}}}
	return svc.Delete(ctx, m.actor, id)
}

func (m *modelT) saveDefaults() error {
	lock, err := util.Acquire(lockFile)
	if err != nil {
		return err
	}
	defer lock.Release()

	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()
	role, err := repo.UserRepo{DB: m.db}.RoleOf(ctx, m.actor)
	if err != nil {
		return err
	}
	if role != "admin" {
		return fmt.Errorf("rbac: need admin, got %s", role)
	}
	m.policies.LogPrefix = m.logInput.Value()
	ds := service.DefaultsService{Repo: repo.DefaultsRepo{DB: m.db}}
	if err := ds.Set(ctx, m.policies); err != nil {
		return err
	}
	_ = service.AuditService{Repo: repo.AuditRepo{DB: m.db}}.Log(ctx, m.actor, "set_defaults", "defaults:1",
		map[string]string{"input": m.policies.InputPolicy, "forward": m.policies.ForwardPolicy, "output": m.policies.OutputPolicy, "log": m.policies.LogPrefix})
	return nil
}

func (m *modelT) saveNewRule() error {
	vals := make([]string, 0, len(m.addInputs))
	for _, in := range m.addInputs {
		vals = append(vals, strings.TrimSpace(in.Value()))
	}
	chain := orDefault(vals[0], "input")
	proto := orDefault(vals[1], "all")
	action := orDefault(vals[2], "accept")
	inIf := strings.TrimSpace(vals[3])
	outIf := strings.TrimSpace(vals[4])
	ports := strings.TrimSpace(vals[5])
	src := strings.TrimSpace(vals[6])
	dst := strings.TrimSpace(vals[7])
	comment := strings.TrimSpace(vals[8])

	if !inSet(strings.ToLower(chain), "input", "forward", "output") {
		return fmt.Errorf("invalid chain: %s (use: input|forward|output)", chain)
	}
	if !inSet(strings.ToLower(proto), "all", "tcp", "udp", "icmp") {
		return fmt.Errorf("invalid proto: %s (use: all|tcp|udp|icmp)", proto)
	}
	if !inSet(strings.ToLower(action), "accept", "drop") {
		return fmt.Errorf("invalid action: %s (use: accept|drop)", action)
	}

	var portInts []int
	if ports != "" {
		for _, p := range strings.Split(ports, ",") {
			var v int
			if _, e := fmt.Sscan(strings.TrimSpace(p), &v); e != nil {
				return fmt.Errorf("bad port: %v", e)
			}
			portInts = append(portInts, v)
		}
	}

	r := &model.Rule{
		Chain:    strings.ToLower(chain),
		Proto:    strings.ToLower(proto),
		Action:   strings.ToLower(action),
		Ports:    portInts,
		Enabled:  true,
		SrcCIDRs: csvSplit(src),
		DstCIDRs: csvSplit(dst),
	}
	if inIf != "" {
		r.InIf = &inIf
	}
	if outIf != "" {
		r.OutIf = &outIf
	}
	if comment != "" {
		r.Comment = &comment
	}

	lock, err := util.Acquire(lockFile)
	if err != nil {
		return err
	}
	defer lock.Release()

	ctx, cancel := context.WithTimeout(m.ctx, 8*time.Second)
	defer cancel()
	role, err := repo.UserRepo{DB: m.db}.RoleOf(ctx, m.actor)
	if err != nil {
		return err
	}
	if role != "admin" && role != "operator" {
		return fmt.Errorf("rbac: need operator or admin, got %s", role)
	}
	rr := repo.RuleRepo{DB: m.db}
	as := service.AuditService{Repo: repo.AuditRepo{DB: m.db}}
	svc := service.RulesService{Repo: rr, Audit: as}
	_, err = svc.Add(ctx, m.actor, r)
	return err
}

func inSet(v string, opts ...string) bool {
	for _, o := range opts {
		if v == o {
			return true
		}
	}
	return false
}
func togglePolicy(v string) string {
	if strings.EqualFold(v, "accept") {
		return "drop"
	}
	return "accept"
}
func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func csvSplit(s string) []string {
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

// ---------- Run ----------

func Run(ctx context.Context, dbPath, actor string) error {
	m, err := New(ctx, dbPath, actor)
	if err != nil {
		return err
	}
	defer m.Close()
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
