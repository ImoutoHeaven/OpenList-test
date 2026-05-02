package op

import (
	"context"
	"fmt"
	"net/url"
	stdpath "path"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

type WebDownloadPolicyKind string

const (
	WebDownloadRedirect302 WebDownloadPolicyKind = "redirect_302"
	WebDownloadProxyURL    WebDownloadPolicyKind = "proxy_url"
	WebDownloadNativeProxy WebDownloadPolicyKind = "native_proxy"
)

type WebDownloadNode struct {
	Storage    driver.Driver
	MountPath  string
	RawPath    string
	ActualPath string
	Policy     WebDownloadPolicyKind
}

type WebDownloadRoute struct {
	RequestRawPath       string
	Nodes                []WebDownloadNode
	EffectivePolicy      WebDownloadPolicyKind
	PolicyOwnerIndex     int
	PolicyOwnerStorage   driver.Driver
	PolicyOwnerRawPath   string
	LeafStorage          driver.Driver
	LeafVirtualMountPath string
	LeafMountPath        string
	LeafRawPath          string
	LeafActualPath       string
}

func ResolveWebDownloadRoute(ctx context.Context, rawPath string) (*WebDownloadRoute, error) {
	return resolveWebDownloadRoute(ctx, rawPath, true)
}

func ResolveWebDownloadRoutePreview(ctx context.Context, rawPath string) (*WebDownloadRoute, error) {
	return resolveWebDownloadRoute(ctx, rawPath, false)
}

func resolveWebDownloadRoute(ctx context.Context, rawPath string, advanceBalance bool) (*WebDownloadRoute, error) {
	rawPath = utils.FixAndCleanPath(rawPath)
	ctx = ensureLinkAPIBalanceState(ctx, advanceBalance)

	nodes, err := resolveWebDownloadNodes(ctx, rawPath, map[string]struct{}{}, advanceBalance)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("web download route resolution produced no nodes for %s", rawPath)
	}

	ownerIndex := len(nodes) - 1
	for i, node := range nodes {
		if node.Policy != WebDownloadRedirect302 {
			ownerIndex = i
			break
		}
	}

	owner := nodes[ownerIndex]
	leaf := nodes[len(nodes)-1]
	return &WebDownloadRoute{
		RequestRawPath:       rawPath,
		Nodes:                append([]WebDownloadNode(nil), nodes...),
		EffectivePolicy:      owner.Policy,
		PolicyOwnerIndex:     ownerIndex,
		PolicyOwnerStorage:   owner.Storage,
		PolicyOwnerRawPath:   webDownloadVirtualRawPath(owner.MountPath, owner.ActualPath),
		LeafStorage:          leaf.Storage,
		LeafVirtualMountPath: utils.GetActualMountPath(leaf.MountPath),
		LeafMountPath:        leaf.MountPath,
		LeafRawPath:          leaf.RawPath,
		LeafActualPath:       leaf.ActualPath,
	}, nil
}

func resolveWebDownloadNodes(ctx context.Context, rawPath string, seen map[string]struct{}, advanceBalance bool) ([]WebDownloadNode, error) {
	rawPath = utils.FixAndCleanPath(rawPath)
	if _, ok := seen[rawPath]; ok {
		return nil, fmt.Errorf("cyclic web download path resolution: %s", rawPath)
	}
	seen[rawPath] = struct{}{}

	storage, actualPath, err := getLinkAPIStorageAndActualPath(ctx, rawPath, advanceBalance)
	if err != nil {
		return nil, err
	}

	node := WebDownloadNode{
		Storage:    storage,
		MountPath:  storage.GetStorage().MountPath,
		RawPath:    webDownloadConcreteRawPath(storage.GetStorage().MountPath, actualPath),
		ActualPath: actualPath,
		Policy:     classifyWebDownloadPolicy(storage, stdpath.Base(rawPath)),
	}

	resolver, ok := storage.(linkAPIRawPathResolver)
	if !ok {
		return []WebDownloadNode{node}, nil
	}

	nextRawPath, err := resolver.ResolveLinkAPIRawPath(ctx, rawPath)
	if err != nil {
		return nil, err
	}
	nextRawPath = utils.FixAndCleanPath(nextRawPath)
	if nextRawPath == rawPath {
		return nil, fmt.Errorf("web download path resolver returned the current path: %s", rawPath)
	}

	downstreamNodes, err := resolveWebDownloadNodes(ctx, nextRawPath, seen, advanceBalance)
	if err != nil {
		return nil, err
	}
	return append([]WebDownloadNode{node}, downstreamNodes...), nil
}

// Browser-download policy intentionally ignores WebDAV proxy settings in this iteration.
func classifyWebDownloadPolicy(storage driver.Driver, filename string) WebDownloadPolicyKind {
	if storage == nil {
		return WebDownloadRedirect302
	}
	if storage.GetStorage().DownProxyURL != "" {
		return WebDownloadProxyURL
	}
	if storage.Config().MustProxy() || storage.GetStorage().WebProxy {
		return WebDownloadNativeProxy
	}
	ext := utils.Ext(filename)
	if utils.SliceContains(conf.SlicesMap[conf.ProxyTypes], ext) || utils.SliceContains(conf.SlicesMap[conf.TextTypes], ext) {
		return WebDownloadNativeProxy
	}
	return WebDownloadRedirect302
}

func webDownloadConcreteRawPath(mountPath, actualPath string) string {
	return utils.FixAndCleanPath(stdpath.Join(utils.FixAndCleanPath(mountPath), actualPath))
}

func webDownloadVirtualRawPath(mountPath, actualPath string) string {
	return utils.GetFullPath(mountPath, actualPath)
}

func WebDownloadExternalProxyURL(route *WebDownloadRoute) (string, error) {
	if route == nil || route.PolicyOwnerStorage == nil {
		return "", fmt.Errorf("web download route is incomplete")
	}
	if route.EffectivePolicy != WebDownloadProxyURL {
		return "", fmt.Errorf("web download route policy %q cannot emit external proxy URL", route.EffectivePolicy)
	}
	storage := route.PolicyOwnerStorage.GetStorage()
	if storage == nil || storage.DownProxyURL == "" {
		return "", fmt.Errorf("storage %s cannot emit external proxy URL", route.PolicyOwnerStorage.GetStorage().MountPath)
	}
	return generateDownProxyURL(storage, route.PolicyOwnerRawPath)
}

func WebDownloadCanonicalProxyURL(apiURL string, route *WebDownloadRoute, query url.Values, signRequired bool) (string, error) {
	proxyPath, err := WebDownloadCanonicalProxyPath(route, query, signRequired)
	if err != nil {
		return "", err
	}
	if apiURL == "" {
		return "", fmt.Errorf("api url is required for canonical proxy URL")
	}
	apiURL = strings.TrimSuffix(apiURL, "/")
	return apiURL + proxyPath, nil
}

func WebDownloadCanonicalProxyPath(route *WebDownloadRoute, query url.Values, signRequired bool) (string, error) {
	if route == nil {
		return "", fmt.Errorf("web download route is required")
	}
	query = cloneWebDownloadQuery(query)
	if query == nil {
		query = url.Values{}
	}
	if query.Get("d") != "1" {
		query.Del("d")
	}
	if signRequired {
		query.Set("sign", signDownProxyPath(route.PolicyOwnerRawPath))
	} else {
		query.Del("sign")
	}
	encodedPath := utils.EncodePath(route.PolicyOwnerRawPath, true)
	if encodedQuery := query.Encode(); encodedQuery != "" {
		return fmt.Sprintf("/p%s?%s", encodedPath, encodedQuery), nil
	}
	return fmt.Sprintf("/p%s", encodedPath), nil
}

func WebDownloadLeafLink(ctx context.Context, route *WebDownloadRoute, args model.LinkArgs) (*model.Link, model.Obj, error) {
	if route == nil || route.LeafStorage == nil {
		return nil, nil, fmt.Errorf("web download leaf route is incomplete")
	}
	return Link(ctx, route.LeafStorage, route.LeafActualPath, args)
}

func WebDownloadLeafDirectLink(ctx context.Context, route *WebDownloadRoute, args model.LinkArgs) (*model.Link, model.Obj, error) {
	link, file, err := WebDownloadLeafLink(ctx, route, args)
	if err != nil {
		return nil, nil, err
	}
	if route != nil && route.LeafStorage != nil {
		virtualLeafRawPath := webDownloadVirtualRawPath(route.LeafVirtualMountPath, route.LeafActualPath)
		if isActualDirectLink(ctx, route.LeafStorage.GetStorage(), route.LeafRawPath, link, virtualLeafRawPath) {
			return link, file, nil
		}
	}
	closeLink(link)
	if route == nil || route.LeafStorage == nil {
		return nil, nil, errs.NewErr(errs.NotSupport, "resolved leaf cannot provide a real upstream downloadable URL")
	}
	return nil, nil, errs.NewErr(errs.NotSupport,
		"storage %s cannot provide a real upstream downloadable URL for %s",
		route.LeafStorage.GetStorage().MountPath,
		route.RequestRawPath,
	)
}

func cloneWebDownloadQuery(query url.Values) url.Values {
	if query == nil {
		return nil
	}
	cloned := make(url.Values, len(query))
	for key, values := range query {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}
