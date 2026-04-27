package fs

import (
	"context"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/pkg/errors"
)

func ResolveActualLink(ctx context.Context, path string, args model.LinkArgs) (*model.Link, error) {
	link, err := op.ResolveActualLink(ctx, path, args)
	if err != nil {
		return nil, errors.WithMessage(err, "failed resolve actual link")
	}
	return link, nil
}
