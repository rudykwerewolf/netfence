package util

import (
	"gopkg.in/yaml.v3"
	"os"
)

func WriteYAML(path string, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil { return err }
	return os.WriteFile(path, b, 0644)
}

func ReadYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil { return err }
	return yaml.Unmarshal(b, v)
}
