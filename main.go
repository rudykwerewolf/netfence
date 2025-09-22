package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

/* ========= helpers ========= */

func runCmd(args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func persist(pages *tview.Pages) {
	if out, err := runCmd("netfilter-persistent", "save"); err != nil {
		showError(pages, "netfilter-persistent failed:\n"+out+"\n"+err.Error())
	}
}

func showError(pages *tview.Pages, msg string) {
	modal := tview.NewModal().
		SetText("Error:\n" + msg).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) { pages.RemovePage("err") })
	pages.AddPage("err", modal, true, true)
}

/* ========= form nav (↑↓) ========= */

func withArrows(app *tview.Application, form *tview.Form) {
	idx := 0
	if form.GetFormItemCount() == 0 {
		return
	}
	app.SetFocus(form.GetFormItem(0))

	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyUp:
			if idx > 0 {
				idx--
			}
			app.SetFocus(form.GetFormItem(idx))
			return nil
		case tcell.KeyDown:
			if idx < form.GetFormItemCount()-1 {
				idx++
			}
			app.SetFocus(form.GetFormItem(idx))
			return nil
		}
		return ev
	})
}

/* ========= NAT form ========= */

func natForm(app *tview.Application, pages *tview.Pages) tview.Primitive {
	form := tview.NewForm()
	iface := ""

	form.AddInputField("Interface (for MASQUERADE)", "", 20, nil, func(s string) { iface = s })

	form.AddButton("Add", func() {
		if iface != "" {
			if out, err := runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"); err != nil {
				showError(pages, out+"\n"+err.Error())
				return
			}
			persist(pages)
		}
	})

	form.AddButton("Back", func() { pages.SwitchToPage("menu") })
	form.SetBorder(true).SetTitle(" Add NAT Rule ").SetTitleAlign(tview.AlignLeft)
	withArrows(app, form)
	return form
}

/* ========= Port Forwarding form ========= */

func portForwardForm(app *tview.Application, pages *tview.Pages) tview.Primitive {
	form := tview.NewForm()
	proto := "tcp"
	ext, dip, dport := "", "", ""

	form.AddButton("Protocol: tcp", func() {
		modal := tview.NewModal().
			SetText("Choose protocol").
			AddButtons([]string{"tcp", "udp", "Cancel"}).
			SetDoneFunc(func(_ int, lab string) {
				if lab == "tcp" || lab == "udp" {
					proto = lab
					form.GetButton(0).SetLabel("Protocol: " + proto)
				}
				pages.RemovePage("modal")
			})
		pages.AddPage("modal", modal, true, true)
	})

	form.AddInputField("External port", "", 20, nil, func(s string) { ext = s })
	form.AddInputField("Destination IP", "", 20, nil, func(s string) { dip = s })
	form.AddInputField("Destination port", "", 20, nil, func(s string) { dport = s })

	form.AddButton("Add", func() {
		if ext != "" && dip != "" {
			if dport == "" {
				dport = ext
			}
			if out, err := runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-p", proto, "--dport", ext, "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%s", dip, dport)); err != nil {
				showError(pages, out+"\n"+err.Error())
				return
			}
			if out, err := runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-p", proto, "-d", dip, "--dport", dport, "-j", "MASQUERADE"); err != nil {
				showError(pages, out+"\n"+err.Error())
				return
			}
			if out, err := runCmd("iptables", "-A", "FORWARD", "-p", proto, "-d", dip, "--dport", dport, "-j", "ACCEPT"); err != nil {
				showError(pages, out+"\n"+err.Error())
				return
			}
			persist(pages)
		}
	})

	form.AddButton("Back", func() { pages.SwitchToPage("menu") })
	form.SetBorder(true).SetTitle(" Add Port Forwarding ").SetTitleAlign(tview.AlignLeft)
	withArrows(app, form)
	return form
}

/* ========= Forwarding form ========= */

func forwardForm(app *tview.Application, pages *tview.Pages) tview.Primitive {
	form := tview.NewForm()
	srcIf, dstIf, proto, srcIP, dstIP, sport, dport := "", "", "any", "", "", "", ""

	form.AddInputField("Source interface", "", 20, nil, func(s string) { srcIf = s })
	form.AddInputField("Destination interface", "", 20, nil, func(s string) { dstIf = s })

	form.AddButton("Proto: any", func() {
		modal := tview.NewModal().
			SetText("Choose proto").
			AddButtons([]string{"any", "tcp", "udp", "icmp", "Cancel"}).
			SetDoneFunc(func(_ int, lab string) {
				if lab != "Cancel" {
					proto = lab
					form.GetButton(2).SetLabel("Proto: " + lab)
				}
				pages.RemovePage("modal")
			})
		pages.AddPage("modal", modal, true, true)
	})

	form.AddInputField("Source IP", "", 20, nil, func(s string) { srcIP = s })
	form.AddInputField("Destination IP", "", 20, nil, func(s string) { dstIP = s })
	form.AddInputField("Sport", "", 10, nil, func(s string) { sport = s })
	form.AddInputField("Dport", "", 10, nil, func(s string) { dport = s })

	form.AddButton("Add", func() {
		args := []string{"iptables", "-A", "FORWARD"}
		if srcIf != "" {
			args = append(args, "-i", srcIf)
		}
		if dstIf != "" {
			args = append(args, "-o", dstIf)
		}
		if proto != "" && proto != "any" {
			args = append(args, "-p", proto)
		}
		if srcIP != "" {
			args = append(args, "-s", srcIP)
		}
		if dstIP != "" {
			args = append(args, "-d", dstIP)
		}
		if sport != "" {
			args = append(args, "--sport", sport)
		}
		if dport != "" {
			args = append(args, "--dport", dport)
		}
		args = append(args, "-j", "ACCEPT")

		if out, err := runCmd(args...); err != nil {
			showError(pages, out+"\n"+err.Error())
			return
		}
		persist(pages)
	})

	form.AddButton("Back", func() { pages.SwitchToPage("menu") })
	form.SetBorder(true).SetTitle(" Add Forwarding Rule ").SetTitleAlign(tview.AlignLeft)
	withArrows(app, form)
	return form
}

/* ========= Firewall Rule form ========= */

func ruleForm(app *tview.Application, pages *tview.Pages) tview.Primitive {
	form := tview.NewForm()
	action := "ACCEPT"
	chain := "INPUT"
	proto := ""
	src, dst, sport, dport := "", "", "", ""

	form.AddButton("Action: ACCEPT", func() {
		modal := tview.NewModal().
			SetText("Choose action").
			AddButtons([]string{"ACCEPT", "DROP", "REJECT", "Cancel"}).
			SetDoneFunc(func(_ int, lab string) {
				if lab == "ACCEPT" || lab == "DROP" || lab == "REJECT" {
					action = lab
					form.GetButton(0).SetLabel("Action: " + action)
				}
				pages.RemovePage("modal")
			})
		pages.AddPage("modal", modal, true, true)
	})

	form.AddButton("Chain: INPUT", func() {
		modal := tview.NewModal().
			SetText("Choose chain").
			AddButtons([]string{"INPUT", "FORWARD", "OUTPUT", "Cancel"}).
			SetDoneFunc(func(_ int, lab string) {
				if lab == "INPUT" || lab == "FORWARD" || lab == "OUTPUT" {
					chain = lab
					form.GetButton(1).SetLabel("Chain: " + chain)
				}
				pages.RemovePage("modal")
			})
		pages.AddPage("modal", modal, true, true)
	})

	form.AddButton("Proto: any", func() {
		modal := tview.NewModal().
			SetText("Choose proto").
			AddButtons([]string{"any", "tcp", "udp", "icmp", "Cancel"}).
			SetDoneFunc(func(_ int, lab string) {
				if lab != "Cancel" {
					if lab == "any" {
						proto = ""
					} else {
						proto = lab
					}
					form.GetButton(2).SetLabel("Proto: " + lab)
				}
				pages.RemovePage("modal")
			})
		pages.AddPage("modal", modal, true, true)
	})

	form.AddInputField("Source", "", 20, nil, func(s string) { src = s })
	form.AddInputField("Destination", "", 20, nil, func(s string) { dst = s })
	form.AddInputField("Sport", "", 10, nil, func(s string) { sport = s })
	form.AddInputField("Dport", "", 10, nil, func(s string) { dport = s })

	form.AddButton("Add", func() {
		args := []string{"iptables", "-A", chain}
		if proto != "" {
			args = append(args, "-p", proto)
		}
		if src != "" {
			args = append(args, "-s", src)
		}
		if dst != "" {
			args = append(args, "-d", dst)
		}
		if sport != "" {
			args = append(args, "--sport", sport)
		}
		if dport != "" {
			args = append(args, "--dport", dport)
		}
		args = append(args, "-j", action)

		if out, err := runCmd(args...); err != nil {
			showError(pages, out+"\n"+err.Error())
			return
		}
		persist(pages)
	})

	form.AddButton("Back", func() { pages.SwitchToPage("menu") })
	form.SetBorder(true).SetTitle(" Add Firewall Rule ").SetTitleAlign(tview.AlignLeft)
	withArrows(app, form)
	return form
}

/* ========= Active lists ========= */

func natList(pages *tview.Pages) tview.Primitive {
	list := tview.NewList()
	out, _ := runCmd("iptables-save", "-t", "nat")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "MASQUERADE") {
			rule := l
			list.AddItem(rule, "", 0, nil)
		}
	}
	list.SetBorder(true).SetTitle(" Active NAT Rules ").SetTitleAlign(tview.AlignLeft)
	list.SetDoneFunc(func() { pages.SwitchToPage("actives") })
	return list
}

func pfList(pages *tview.Pages) tview.Primitive {
	list := tview.NewList()
	out, _ := runCmd("iptables-save", "-t", "nat")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "DNAT") {
			rule := l
			list.AddItem(rule, "", 0, nil)
		}
	}
	list.SetBorder(true).SetTitle(" Active Port Forwarding Rules ").SetTitleAlign(tview.AlignLeft)
	list.SetDoneFunc(func() { pages.SwitchToPage("actives") })
	return list
}

func forwardList(pages *tview.Pages) tview.Primitive {
	list := tview.NewList()
	out, _ := runCmd("iptables", "-S", "FORWARD")
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A") {
			rule := l
			list.AddItem(rule, "", 0, nil)
		}
	}
	list.SetBorder(true).SetTitle(" Active Forwarding Rules ").SetTitleAlign(tview.AlignLeft)
	list.SetDoneFunc(func() { pages.SwitchToPage("actives") })
	return list
}

func ruleList(pages *tview.Pages) tview.Primitive {
	list := tview.NewList()
	out, _ := runCmd("iptables", "-S")
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A") && !strings.Contains(l, "FORWARD") {
			rule := l
			list.AddItem(rule, "", 0, nil)
		}
	}
	list.SetBorder(true).SetTitle(" Active Firewall Rules ").SetTitleAlign(tview.AlignLeft)
	list.SetDoneFunc(func() { pages.SwitchToPage("actives") })
	return list
}

/* ========= Active submenu ========= */

func activeMenu(pages *tview.Pages) tview.Primitive {
	list := tview.NewList().
		AddItem("Active NAT Rules", "", '1', func() { pages.SwitchToPage("natlist") }).
		AddItem("Active Port Forwarding Rules", "", '2', func() { pages.SwitchToPage("pflist") }).
		AddItem("Active Forwarding Rules", "", '3', func() { pages.SwitchToPage("fwdlist") }).
		AddItem("Active Firewall Rules", "", '4', func() { pages.SwitchToPage("rulelist") }).
		AddItem("Back", "", 'b', func() { pages.SwitchToPage("menu") })
	list.SetBorder(true).SetTitle(" Active Rules ").SetTitleAlign(tview.AlignLeft)
	return list
}

/* ========= System ========= */

func sysForm(app *tview.Application, pages *tview.Pages) tview.Primitive {
	form := tview.NewForm()
	form.AddButton("Enable IPv4 forwarding", func() {
		if out, err := runCmd("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			showError(pages, out+"\n"+err.Error())
		}
	}).
		AddButton("Status", func() {
			out, err := runCmd("sysctl", "net.ipv4.ip_forward")
			if err != nil {
				showError(pages, out+"\n"+err.Error())
				return
			}
			modal := tview.NewModal().
				SetText(out).
				AddButtons([]string{"OK"}).
				SetDoneFunc(func(_ int, _ string) { pages.RemovePage("modal") })
			pages.AddPage("modal", modal, true, true)
		}).
		AddButton("Back", func() { pages.SwitchToPage("menu") })
	form.SetBorder(true).SetTitle(" System ").SetTitleAlign(tview.AlignLeft)
	withArrows(app, form)
	return form
}

/* ========= Main ========= */

func main() {
	app := tview.NewApplication()
	pages := tview.NewPages()

	menu := tview.NewList().
		AddItem("Active Rules", "", '1', func() { pages.SwitchToPage("actives") }).
		AddItem("Add NAT Rule", "", '2', func() { pages.SwitchToPage("nat") }).
		AddItem("Add Port Forwarding", "", '3', func() { pages.SwitchToPage("portfwd") }).
		AddItem("Add Forwarding Rule", "", '4', func() { pages.SwitchToPage("forward") }).
		AddItem("Add Firewall Rule", "", '5', func() { pages.SwitchToPage("rule") }).
		AddItem("System", "", '6', func() { pages.SwitchToPage("system") }).
		AddItem("Save & Exit", "", 's', func() { persist(pages); app.Stop() }).
		AddItem("Exit without saving", "", 'q', func() { app.Stop() })
	menu.SetBorder(true).SetTitle(" NetFence ").SetTitleAlign(tview.AlignLeft)

	pages.AddPage("menu", menu, true, true).
		AddPage("nat", natForm(app, pages), true, false).
		AddPage("portfwd", portForwardForm(app, pages), true, false).
		AddPage("forward", forwardForm(app, pages), true, false).
		AddPage("rule", ruleForm(app, pages), true, false).
		AddPage("actives", activeMenu(pages), true, false).
		AddPage("natlist", natList(pages), true, false).
		AddPage("pflist", pfList(pages), true, false).
		AddPage("fwdlist", forwardList(pages), true, false).
		AddPage("rulelist", ruleList(pages), true, false).
		AddPage("system", sysForm(app, pages), true, false)

	if err := app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
