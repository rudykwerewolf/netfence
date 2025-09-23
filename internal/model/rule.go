package model

type Rule struct {
	ID        int64
	Chain     string
	Proto     string
	Action    string
	InIf      *string
	OutIf     *string
	Ports     []int
	SrcCIDRs  []string
	DstCIDRs  []string
	ICMPTypes []int
	Comment   *string
	Enabled   bool
}
