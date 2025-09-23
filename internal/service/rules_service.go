package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"example.com/netfence/internal/model"
	"example.com/netfence/internal/repo"
	"example.com/netfence/internal/util"
)

type RulesService struct {
	Repo   repo.RuleRepo
	Audit  AuditService
}

var ErrInvalid = errors.New("invalid rule")

func (s RulesService) List(ctx context.Context, enabledOnly bool) ([]model.Rule, error) {
	return s.Repo.List(ctx, enabledOnly)
}
func (s RulesService) Add(ctx context.Context, actor string, r *model.Rule) (int64, error) {
	if err := validateRule(r); err != nil { return 0, err }
	// validate interfaces exist
	if r.InIf != nil { if err := util.IfExists(*r.InIf); err != nil { return 0, err } }
	if r.OutIf != nil { if err := util.IfExists(*r.OutIf); err != nil { return 0, err } }
	id, err := s.Repo.Create(ctx, r)
	if err == nil { _ = s.Audit.Log(ctx, actor, "add_rule", fmt.Sprintf("rule:%d", id), r) }
	return id, err
}
func (s RulesService) Delete(ctx context.Context, actor string, id int64) error {
	err := s.Repo.Delete(ctx, id)
	if err == nil { _ = s.Audit.Log(ctx, actor, "del_rule", fmt.Sprintf("rule:%d", id), nil) }
	return err
}

func validateRule(r *model.Rule) error {
	if !oneOf(r.Chain,"input","forward","output") { return Err("chain") }
	if !oneOf(r.Proto,"all","tcp","udp","icmp") { return Err("proto") }
	if !oneOf(r.Action,"accept","drop") { return Err("action") }
	for _, p := range r.Ports { if p<=0 || p>65535 { return Err("port") } }
	for _, c := range r.SrcCIDRs { if _,_,e:=net.ParseCIDR(c); e!=nil { return Err("src_cidr") } }
	for _, c := range r.DstCIDRs { if _,_,e:=net.ParseCIDR(c); e!=nil { return Err("dst_cidr") } }
	for _, t := range r.ICMPTypes { if t<0 || t>255 { return Err("icmp_type") } }
	if r.InIf!=nil && strings.TrimSpace(*r.InIf)=="" { return Err("in_if") }
	if r.OutIf!=nil && strings.TrimSpace(*r.OutIf)=="" { return Err("out_if") }
	return nil
}
func oneOf(v string, xs ...string) bool { for _,x:= range xs { if v==x { return true } }; return false }
func Err(field string) error { return fmt.Errorf("%w: %s", ErrInvalid, field) }
