package util

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

func IfExists(name string) error {
	if name == "" { return nil }
	_, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", name, err)
	}
	return nil
}
