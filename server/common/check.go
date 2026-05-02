package common

import (
	"context"
	"path"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/dlclark/regexp2"
	perrors "github.com/pkg/errors"
)

func IsStorageSignEnabled(rawPath string) bool {
	storage := op.PeekBalancedStorage(rawPath)
	return storage != nil && storage.GetStorage().EnableSign
}

func IsStorageSignEnabledForRequest(ctx context.Context, rawPath string) bool {
	rawPath = utils.FixAndCleanPath(rawPath)
	ctx = op.EnsureLinkAPIBalanceStateForRequest(ctx)
	storage := op.ResolveLinkAPIStorageForSignCheck(ctx, rawPath)
	return storage != nil && storage.GetStorage().EnableSign
}

func IsPathSignRequired(rawPath string) (bool, error) {
	rawPath = utils.FixAndCleanPath(rawPath)
	return isPathSignRequiredForStorage(rawPath, op.PeekBalancedStorage(rawPath))
}

func IsPathSignRequiredForStorage(rawPath string, storage driver.Driver) (bool, error) {
	rawPath = utils.FixAndCleanPath(rawPath)
	return isPathSignRequiredForStorage(rawPath, storage)
}

func isPathSignRequiredForStorage(rawPath string, storage driver.Driver) (bool, error) {
	if setting.GetBool(conf.SignAll) {
		return true, nil
	}
	if storage != nil && storage.GetStorage().EnableSign {
		return true, nil
	}
	meta, err := op.GetNearestMeta(rawPath)
	if err != nil {
		if perrors.Is(perrors.Cause(err), errs.MetaNotFound) {
			return false, nil
		}
		return false, err
	}
	return MetaRequiresSign(meta, rawPath), nil
}

func IsPathSignRequiredForRequest(ctx context.Context, rawPath string) (context.Context, bool, error) {
	rawPath = utils.FixAndCleanPath(rawPath)
	ctx = op.EnsureLinkAPIBalanceStateForRequest(ctx)
	needSign, err := isPathSignRequiredForStorage(rawPath, op.ResolveLinkAPIStorageForSignCheck(ctx, rawPath))
	return ctx, needSign, err
}

func MetaRequiresSign(meta *model.Meta, rawPath string) bool {
	if meta == nil || meta.Password == "" {
		return false
	}
	if !meta.PSub && !utils.PathEqual(meta.Path, rawPath) {
		return false
	}
	return true
}

func CanWrite(meta *model.Meta, path string) bool {
	if meta == nil || !meta.Write {
		return false
	}
	return meta.WSub || meta.Path == path
}

func IsApply(metaPath, reqPath string, applySub bool) bool {
	if utils.PathEqual(metaPath, reqPath) {
		return true
	}
	return utils.IsSubPath(metaPath, reqPath) && applySub
}

func CanAccess(user *model.User, meta *model.Meta, reqPath string, password string) bool {
	// if the reqPath is in hide (only can check the nearest meta) and user can't see hides, can't access
	if meta != nil && !user.CanSeeHides() && meta.Hide != "" &&
		IsApply(meta.Path, path.Dir(reqPath), meta.HSub) { // the meta should apply to the parent of current path
		for _, hide := range strings.Split(meta.Hide, "\n") {
			re := regexp2.MustCompile(hide, regexp2.None)
			if isMatch, _ := re.MatchString(path.Base(reqPath)); isMatch {
				return false
			}
		}
	}
	// if is not guest and can access without password
	if user.CanAccessWithoutPassword() {
		return true
	}
	// if meta is nil or password is empty, can access
	if meta == nil || meta.Password == "" {
		return true
	}
	// if meta doesn't apply to sub_folder, can access
	if !utils.PathEqual(meta.Path, reqPath) && !meta.PSub {
		return true
	}
	// validate password
	return meta.Password == password
}

// ShouldProxy TODO need optimize
// when should be proxy?
// 1. config.MustProxy()
// 2. storage.WebProxy
// 3. proxy_types
func ShouldProxy(storage driver.Driver, filename string) bool {
	if storage.Config().MustProxy() || storage.GetStorage().WebProxy {
		return true
	}
	if utils.SliceContains(conf.SlicesMap[conf.ProxyTypes], utils.Ext(filename)) {
		return true
	}
	return false
}
