package op

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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

func EnsureLinkAPIBalanceStateForRequest(ctx context.Context) context.Context {
	return ensureLinkAPIBalanceState(ctx, true)
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

func ResolveLinkAPIStorageForSignCheck(ctx context.Context, rawPath string) driver.Driver {
	rawPath = utils.FixAndCleanPath(rawPath)
	return getLinkAPIStorage(ctx, rawPath, false)
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
	storage, actualPath, resolvedVirtualRawPath, err := ResolveActualStoragePath(ctx, rawPath)
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
	resolvedConcreteRawPath := webDownloadConcreteRawPath(storage.GetStorage().MountPath, actualPath)
	if isActualDirectLink(ctx, storage.GetStorage(), resolvedConcreteRawPath, link, resolvedVirtualRawPath) {
		return link, nil
	}
	closeLink(link)

	return nil, errs.NewErr(errs.NotSupport,
		"storage %s cannot provide a real upstream downloadable URL for %s",
		storage.GetStorage().MountPath, rawPath,
	)
}

func isActualDirectLink(ctx context.Context, storage *model.Storage, resolvedRawPath string, link *model.Link, additionalRawPaths ...string) bool {
	if link == nil || link.URL == "" {
		return false
	}
	parsedURL, err := url.Parse(link.URL)
	if err != nil || !parsedURL.IsAbs() || parsedURL.Host == "" {
		return false
	}
	if isOpenListLocalURL(ctx, parsedURL) {
		return false
	}
	if isDownProxyDerivedURL(storage, resolvedRawPath, parsedURL) {
		return false
	}
	for _, rawPath := range additionalRawPaths {
		if utils.FixAndCleanPath(rawPath) == utils.FixAndCleanPath(resolvedRawPath) {
			continue
		}
		if isDownProxyDerivedURL(storage, rawPath, parsedURL) {
			return false
		}
	}
	return true
}

func isDownProxyDerivedURL(storage *model.Storage, resolvedRawPath string, parsedURL *url.URL) bool {
	if storage == nil || storage.DownProxyURL == "" {
		return false
	}
	baseURL := strings.Split(storage.DownProxyURL, "\n")[0]
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil || !parsedBaseURL.IsAbs() || parsedBaseURL.Host == "" {
		return false
	}
	if !strings.EqualFold(parsedBaseURL.Scheme, parsedURL.Scheme) || !strings.EqualFold(parsedBaseURL.Host, parsedURL.Host) {
		return false
	}
	if malformedDownProxyBaseDerivedURL(parsedBaseURL, resolvedRawPath, parsedURL) {
		return true
	}
	generatedURL, err := generateDownProxyURL(storage, resolvedRawPath)
	if err != nil || generatedURL == "" {
		return false
	}
	generatedParsedURL, err := url.Parse(generatedURL)
	if err != nil || !generatedParsedURL.IsAbs() || generatedParsedURL.Host == "" {
		return false
	}
	if !strings.EqualFold(generatedParsedURL.Scheme, parsedURL.Scheme) || !strings.EqualFold(generatedParsedURL.Host, parsedURL.Host) {
		return false
	}
	if generatedParsedURL.Path != parsedURL.Path {
		return false
	}
	return true
}

func malformedDownProxyBaseDerivedURL(baseURL *url.URL, resolvedRawPath string, parsedURL *url.URL) bool {
	if baseURL == nil {
		return false
	}
	if baseURL.RawQuery == "" && baseURL.Fragment == "" {
		return false
	}
	return strings.HasPrefix(parsedURL.String(), baseURL.String()+utils.EncodePath(resolvedRawPath, true))
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
	localPath := utils.FixAndCleanPath(parsedURL.Path)
	if utils.IsSubPath(utils.FixAndCleanPath(parsedAPIURL.Path), localPath) {
		return true
	}
	return utils.IsSubPath("/p", localPath) || utils.IsSubPath("/d", localPath)
}

func generateDownProxyURL(storage *model.Storage, reqPath string) (string, error) {
	if storage == nil || storage.DownProxyURL == "" {
		return "", nil
	}
	baseURL := strings.Split(storage.DownProxyURL, "\n")[0]
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil || !parsedBaseURL.IsAbs() || parsedBaseURL.Host == "" || parsedBaseURL.RawQuery != "" || parsedBaseURL.Fragment != "" {
		return "", fmt.Errorf("storage %s has invalid external down_proxy_url %q", storage.MountPath, baseURL)
	}
	query := ""
	if !storage.DisableProxySign {
		query = "?sign=" + signDownProxyPath(reqPath)
	}
	generatedURL := fmt.Sprintf("%s%s%s",
		baseURL,
		utils.EncodePath(reqPath, true),
		query,
	)
	parsedGeneratedURL, err := url.Parse(generatedURL)
	if err != nil || !parsedGeneratedURL.IsAbs() || parsedGeneratedURL.Host == "" {
		return "", fmt.Errorf("storage %s has invalid external down_proxy_url %q", storage.MountPath, baseURL)
	}
	return generatedURL, nil
}

func signDownProxyPath(data string) string {
	expire := getSettingInt(conf.LinkExpiration)
	expireAt := int64(0)
	if expire > 0 {
		expireAt = time.Now().Add(time.Duration(expire) * time.Hour).Unix()
	}
	return newLinkAPISigner().Sign(data, expireAt)
}

func RefreshLinkAPISigner() {
	// No cached signer remains in internal/op; signer state is derived per call.
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
