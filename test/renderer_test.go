package test

import (
	"testing"
	"example.com/netfence/internal/model"
	"example.com/netfence/internal/render"
	"strings"
)

func TestRenderBasic(t *testing.T){
	def := model.Defaults{InputPolicy:"drop",ForwardPolicy:"drop",OutputPolicy:"accept",LogPrefix:""}
	rules := []model.Rule{ {Chain:"input", Proto:"tcp", Action:"accept", Ports:[]int{22}, SrcCIDRs:[]string{"0.0.0.0/0"}, Enabled:true} }
	s := render.Render(def, rules)
	if !strings.Contains(s, "th dport { 22 }") { t.Fatal("missing port 22") }
	if !strings.Contains(s, "policy drop") { t.Fatal("missing policy drop") }
}
