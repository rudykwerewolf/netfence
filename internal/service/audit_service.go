package service

import (
	"context"
	"encoding/json"
	"netfence/internal/repo"
)

type AuditService struct{ Repo repo.AuditRepo }

func (s AuditService) Log(ctx context.Context, actor, action, object string, details any) error {
	var dstr string
	if details != nil {
		b, _ := json.Marshal(details); dstr = string(b)
	} else { dstr = "{}" }
	return s.Repo.Write(ctx, actor, action, object, dstr)
}

