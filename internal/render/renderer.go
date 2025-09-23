package render

import (
	"fmt"
	"strings"

	"example.com/netfence/internal/model"
)

// Render собирает ruleset в правильный синтаксис nftables
func Render(def model.Defaults, rules []model.Rule) string {
	var b strings.Builder

	b.WriteString("flush ruleset\n\n")
	b.WriteString("table inet netfence {\n")

	// цепочки
	renderChain(&b, "input", def.InputPolicy, rules)
	renderChain(&b, "forward", def.ForwardPolicy, rules)
	renderChain(&b, "output", def.OutputPolicy, rules)

	b.WriteString("}\n")
	return b.String()
}

func renderChain(b *strings.Builder, name, policy string, rules []model.Rule) {
	fmt.Fprintf(b, "  chain %s {\n", name)
	fmt.Fprintf(b, "    type filter hook %s priority 0; policy %s;\n", name, policy)

	// базовое правило: пропускаем established/related
	b.WriteString("    ct state established,related accept\n")

	// правила из БД
	for _, r := range rules {
		if r.Chain != name || !r.Enabled {
			continue
		}
		line := renderRule(r)
		if line != "" {
			fmt.Fprintf(b, "    %s\n", line)
		}
	}

	b.WriteString("  }\n\n")
}

// renderRule превращает Rule в строку nft
func renderRule(r model.Rule) string {
	var parts []string

	if r.InIf != nil {
		parts = append(parts, fmt.Sprintf(`iifname "%s"`, *r.InIf))
	}
	if r.OutIf != nil {
		parts = append(parts, fmt.Sprintf(`oifname "%s"`, *r.OutIf))
	}
	if r.Proto != "all" {
		switch r.Proto {
		case "tcp", "udp":
			parts = append(parts, "ip protocol "+r.Proto)
		case "icmp":
			parts = append(parts, "ip protocol icmp")
		}
	}
	if len(r.Ports) > 0 && (r.Proto == "tcp" || r.Proto == "udp") {
		var s []string
		for _, p := range r.Ports {
			s = append(s, fmt.Sprintf("%d", p))
		}
		parts = append(parts, fmt.Sprintf("%s dport { %s }", r.Proto, strings.Join(s, ",")))
	}
	for _, cidr := range r.SrcCIDRs {
		parts = append(parts, fmt.Sprintf("ip saddr %s", cidr))
	}
	for _, cidr := range r.DstCIDRs {
		parts = append(parts, fmt.Sprintf("ip daddr %s", cidr))
	}
	if len(r.ICMPTypes) > 0 && r.Proto == "icmp" {
		var s []string
		for _, t := range r.ICMPTypes {
			s = append(s, fmt.Sprintf("%d", t))
		}
		parts = append(parts, fmt.Sprintf("icmp type { %s }", strings.Join(s, ",")))
	}

	parts = append(parts, r.Action)
	return strings.Join(parts, " ")
}
