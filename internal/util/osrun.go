package util

import (
	"bytes"
//	"fmt"
	"os/exec"
)

type Runner interface {
	Run(name string, stdin []byte, args ...string) (string, string, error)
}

type ShellRunner struct{}

func (ShellRunner) Run(name string, stdin []byte, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if stdin != nil { cmd.Stdin = bytes.NewReader(stdin) }
	err := cmd.Run()
	return out.String(), errb.String(), err
}
