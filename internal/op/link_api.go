package op

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	pkgsign "github.com/OpenListTeam/OpenList/v4/pkg/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

type linkAPIRawPathResolver interface {
	ResolveLinkAPIRawPath(ctx context.Context, rawPath string) (string, error)
}

type linkAPIBalanceState struct {
	pinnedMountPath       map[string]string
	reserveBalanceOnProbe bool
}

type linkAPIBalanceStateKey struct{}
type linkAPIProbeSeenKey struct{}

var linkAPISignerMu sync.Mutex
var linkAPISignerOnce sync.Once
var linkAPISigner pkgsign.Sign

func HasLinkAPIStorage(rawPath string) bool {
	rawPath = utils.FixAndCleanPath(rawPath)
	return len(getStoragesByPath(rawPath)) > 0
}

func HasLinkAPIObject(ctx context.Context, rawPath string) bool {
	ctx = ensureLinkAPIBalanceState(ctx, false)
	ctx, seen := ensureLinkAPIProbeSeen(ctx)
	seen = cloneLinkAPIProbeSeen(seen)
	ctx = context.WithValue(ctx, linkAPIProbeSeenKey{}, seen)
	state := getLinkAPIBalanceState(ctx)
	probeState := cloneLinkAPIBalanceState(state)
	probeCtx := context.WithValue(ctx, linkAPIBalanceStateKey{}, probeState)
	ok := hasLinkAPIObject(probeCtx, utils.FixAndCleanPath(rawPath), seen)
	commitLinkAPIBalanceState(state, probeState)
	return ok
}

func HasLinkAPIObjectWithSeen(ctx context.Context, rawPath string, seen map[string]struct{}) bool {
	ctx = ensureLinkAPIBalanceState(ctx, false)
	seen = cloneLinkAPIProbeSeen(seen)
	ctx = context.WithValue(ctx, linkAPIProbeSeenKey{}, seen)
	return hasLinkAPIObject(ctx, rawPath, seen)
}

func hasLinkAPIObject(ctx context.Context, rawPath string, seen map[string]struct{}) bool {
	rawPath = utils.FixAndCleanPath(rawPath)
	if _, ok := seen[rawPath]; ok {
		return false
	}
	seen[rawPath] = struct{}{}

	storage, actualPath, err := getLinkAPIStorageAndActualPath(ctx, rawPath, false)
	if err != nil {
		return false
	}
	if resolver, ok := storage.(linkAPIRawPathResolver); ok {
		nextRawPath, err := resolver.ResolveLinkAPIRawPath(ctx, rawPath)
		if err != nil {
			return false
		}
		nextRawPath = utils.FixAndCleanPath(nextRawPath)
		if nextRawPath == rawPath {
			return false
		}
		return hasLinkAPIObject(ctx, nextRawPath, seen)
	}

	obj, err := GetUnwrap(ctx, storage, actualPath)
	return err == nil && obj != nil
}

func ensureLinkAPIBalanceState(ctx context.Context, reserveBalanceOnProbe bool) context.Context {
	if state := getLinkAPIBalanceState(ctx); state != nil {
		if reserveBalanceOnProbe {
			state.reserveBalanceOnProbe = true
		}
		return ctx
	}
	return context.WithValue(ctx, linkAPIBalanceStateKey{}, &linkAPIBalanceState{
		pinnedMountPath:       map[string]string{},
		reserveBalanceOnProbe: reserveBalanceOnProbe,
	})
}

func getLinkAPIBalanceState(ctx context.Context) *linkAPIBalanceState {
	state, _ := ctx.Value(linkAPIBalanceStateKey{}).(*linkAPIBalanceState)
	return state
}

func ensureLinkAPIProbeSeen(ctx context.Context) (context.Context, map[string]struct{}) {
	if seen := getLinkAPIProbeSeen(ctx); seen != nil {
		return ctx, seen
	}
	seen := map[string]struct{}{}
	return context.WithValue(ctx, linkAPIProbeSeenKey{}, seen), seen
}

func getLinkAPIProbeSeen(ctx context.Context) map[string]struct{} {
	seen, _ := ctx.Value(linkAPIProbeSeenKey{}).(map[string]struct{})
	return seen
}

func cloneLinkAPIProbeSeen(seen map[string]struct{}) map[string]struct{} {
	cloned := map[string]struct{}{}
	for path := range seen {
		cloned[path] = struct{}{}
	}
	return cloned
}

func cloneLinkAPIBalanceState(state *linkAPIBalanceState) *linkAPIBalanceState {
	cloned := &linkAPIBalanceState{
		pinnedMountPath:       map[string]string{},
		reserveBalanceOnProbe: state != nil && state.reserveBalanceOnProbe,
	}
	if state == nil {
		return cloned
	}
	for virtualPath, mountPath := range state.pinnedMountPath {
		cloned.pinnedMountPath[virtualPath] = mountPath
	}
	return cloned
}

func commitLinkAPIBalanceState(dst, src *linkAPIBalanceState) {
	if dst == nil || src == nil {
		return
	}
	for virtualPath, mountPath := range src.pinnedMountPath {
		if existing, ok := dst.pinnedMountPath[virtualPath]; ok && existing == mountPath {
			continue
		}
		dst.pinnedMountPath[virtualPath] = mountPath
	}
	dst.reserveBalanceOnProbe = dst.reserveBalanceOnProbe || src.reserveBalanceOnProbe
}

func getLinkAPIStorageAndActualPath(ctx context.Context, rawPath string, advanceBalance bool) (driver.Driver, string, error) {
	rawPath = utils.FixAndCleanPath(rawPath)
	storage := getLinkAPIStorage(ctx, rawPath, advanceBalance)
	if storage == nil {
		if rawPath == "/" {
			return nil, "", errs.NewErr(errs.StorageNotFound, "please add a storage first")
		}
		return nil, "", errs.NewErr(errs.StorageNotFound, "rawPath: %s", rawPath)
	}
	mountPath := utils.GetActualMountPath(storage.GetStorage().MountPath)
	actualPath := utils.FixAndCleanPath(strings.TrimPrefix(rawPath, mountPath))
	return storage, actualPath, nil
}

func getLinkAPIStorage(ctx context.Context, path string, advanceBalance bool) driver.Driver {
	path = utils.FixAndCleanPath(path)
	storages := getStoragesByPath(path)
	switch len(storages) {
	case 0:
		return nil
	case 1:
		return storages[0]
	default:
		state := getLinkAPIBalanceState(ctx)
		virtualPath := utils.GetActualMountPath(storages[0].GetStorage().MountPath)
		if state != nil {
			if mountPath, ok := state.pinnedMountPath[virtualPath]; ok {
				for _, storage := range storages {
					if storage.GetStorage().MountPath == mountPath {
						return storage
					}
				}
				delete(state.pinnedMountPath, virtualPath)
			}
		}
		if advanceBalance {
			chosen := GetBalancedStorage(path)
			if chosen != nil && state != nil {
				state.pinnedMountPath[virtualPath] = chosen.GetStorage().MountPath
			}
			return chosen
		}
		if state != nil && state.reserveBalanceOnProbe {
			chosen := GetBalancedStorage(path)
			if chosen != nil {
				state.pinnedMountPath[virtualPath] = chosen.GetStorage().MountPath
			}
			return chosen
		}
		i, ok := balanceMap.Load(virtualPath)
		if !ok {
			i = 0
		}
		next := (i + 1) % len(storages)
		chosen := storages[next]
		if state != nil {
			state.pinnedMountPath[virtualPath] = chosen.GetStorage().MountPath
		}
		return chosen
	}
}

func ResolveActualStoragePath(ctx context.Context, rawPath string) (driver.Driver, string, string, error) {
	ctx = ensureLinkAPIBalanceState(ctx, true)
	return resolveActualStoragePath(ctx, utils.FixAndCleanPath(rawPath), map[string]struct{}{})
}

func resolveActualStoragePath(ctx context.Context, rawPath string, seen map[string]struct{}) (driver.Driver, string, string, error) {
	rawPath = utils.FixAndCleanPath(rawPath)
	if _, ok := seen[rawPath]; ok {
		return nil, "", "", fmt.Errorf("cyclic Link API path resolution: %s", rawPath)
	}
	seen[rawPath] = struct{}{}

	storage, actualPath, err := getLinkAPIStorageAndActualPath(ctx, rawPath, true)
	if err != nil {
		return nil, "", "", err
	}
	if resolver, ok := storage.(linkAPIRawPathResolver); ok {
		nextRawPath, err := resolver.ResolveLinkAPIRawPath(ctx, rawPath)
		if err != nil {
			return nil, "", "", err
		}
		nextRawPath = utils.FixAndCleanPath(nextRawPath)
		if nextRawPath == rawPath {
			return nil, "", "", fmt.Errorf("link API path resolver returned the current path: %s", rawPath)
		}
		return resolveActualStoragePath(ctx, nextRawPath, seen)
	}

	return storage, actualPath, utils.GetFullPath(storage.GetStorage().MountPath, actualPath), nil
}

func ResolveActualLink(ctx context.Context, rawPath string, args model.LinkArgs) (*model.Link, error) {
	storage, actualPath, resolvedRawPath, err := ResolveActualStoragePath(ctx, rawPath)
	if err != nil {
		return nil, err
	}

	file, err := GetUnwrap(ctx, storage, actualPath)
	if err != nil {
		return nil, err
	}
	if file == nil {
		return nil, errs.ObjectNotFound
	}
	if file.IsDir() {
		return nil, errs.NotFile
	}

	leafArgs := args
	leafArgs.Redirect = false
	link, err := storage.Link(ctx, file, leafArgs)
	if err != nil {
		return nil, err
	}
	if isActualDirectLink(ctx, link) {
		return link, nil
	}
	closeLink(link)

	downProxyURL := generateDownProxyURL(storage.GetStorage(), resolvedRawPath)
	if downProxyURL != "" {
		return &model.Link{URL: downProxyURL}, nil
	}

	return nil, errs.NewErr(errs.NotSupport,
		"storage %s cannot provide an external downloadable URL for %s",
		storage.GetStorage().MountPath, resolvedRawPath,
	)
}

func isActualDirectLink(ctx context.Context, link *model.Link) bool {
	if link == nil || link.URL == "" {
		return false
	}
	parsedURL, err := url.Parse(link.URL)
	if err != nil || !parsedURL.IsAbs() || parsedURL.Host == "" {
		return false
	}
	return !isOpenListLocalURL(ctx, parsedURL)
}

func isOpenListLocalURL(ctx context.Context, parsedURL *url.URL) bool {
	apiURL, _ := ctx.Value(conf.ApiUrlKey).(string)
	apiURL = strings.TrimSuffix(apiURL, "/")
	if apiURL == "" {
		return false
	}
	parsedAPIURL, err := url.Parse(apiURL)
	if err != nil || !parsedAPIURL.IsAbs() || parsedAPIURL.Host == "" {
		return false
	}
	if !strings.EqualFold(parsedAPIURL.Scheme, parsedURL.Scheme) || !strings.EqualFold(parsedAPIURL.Host, parsedURL.Host) {
		return false
	}
	return utils.IsSubPath(utils.FixAndCleanPath(parsedAPIURL.Path), utils.FixAndCleanPath(parsedURL.Path))
}

func generateDownProxyURL(storage *model.Storage, reqPath string) string {
	if storage.DownProxyURL == "" {
		return ""
	}
	query := ""
	if !storage.DisableProxySign {
		query = "?sign=" + signDownProxyPath(reqPath)
	}
	return fmt.Sprintf("%s%s%s",
		strings.Split(storage.DownProxyURL, "\n")[0],
		utils.EncodePath(reqPath, true),
		query,
	)
}

func signDownProxyPath(data string) string {
	linkAPISignerOnce.Do(initLinkAPISigner)
	expire := getSettingInt(conf.LinkExpiration)
	expireAt := int64(0)
	if expire > 0 {
		expireAt = time.Now().Add(time.Duration(expire) * time.Hour).Unix()
	}
	return linkAPISigner.Sign(data, expireAt)
}

func RefreshLinkAPISigner() {
	linkAPISignerMu.Lock()
	defer linkAPISignerMu.Unlock()
	linkAPISigner = newLinkAPISigner()
	linkAPISignerOnce = sync.Once{}
	linkAPISignerOnce.Do(func() {
		if linkAPISigner == nil {
			linkAPISigner = newLinkAPISigner()
		}
	})
}

func initLinkAPISigner() {
	linkAPISignerMu.Lock()
	defer linkAPISignerMu.Unlock()
	if linkAPISigner == nil {
		linkAPISigner = newLinkAPISigner()
	}
}

func newLinkAPISigner() pkgsign.Sign {
	return pkgsign.NewHMACSign([]byte(getSettingValue(conf.Token)))
}

func getSettingValue(key string) string {
	item, err := GetSettingItemByKey(key)
	if err != nil || item == nil {
		return ""
	}
	return item.Value
}

func getSettingInt(key string) int {
	value := getSettingValue(key)
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func closeLink(link *model.Link) {
	if link != nil {
		_ = link.Close()
	}
}
