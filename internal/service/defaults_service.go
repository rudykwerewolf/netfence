package service

import (
	"context"
	"errors"
	"netfence/internal/model"
	"netfence/internal/repo"
	"strings"
)

type DefaultsService struct{ Repo repo.DefaultsRepo }

func (s DefaultsService) Get(ctx context.Context) (model.Defaults, error) { return s.Repo.Get(ctx) }
func (s DefaultsService) Set(ctx context.Context, d model.Defaults) error {
	if !validPolicy(d.InputPolicy)||!validPolicy(d.ForwardPolicy)||!validPolicy(d.OutputPolicy) {
		return errors.New("invalid policy")
	}
	return s.Repo.Set(ctx, d)
}
func validPolicy(p string) bool { p=strings.ToLower(p); return p=="accept"||p=="drop" }
