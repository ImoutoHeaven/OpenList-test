package handles

import (
	"context"
	"fmt"
	stdpath "path"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

type ListReq struct {
	model.PageReq
	Path     string `json:"path" form:"path"`
	Password string `json:"password" form:"password"`
	Refresh  bool   `json:"refresh"`
}

type DirReq struct {
	Path      string `json:"path" form:"path"`
	Password  string `json:"password" form:"password"`
	ForceRoot bool   `json:"force_root" form:"force_root"`
}

type ObjResp struct {
	Id           string                        `json:"id"`
	Path         string                        `json:"path"`
	Name         string                        `json:"name"`
	Size         int64                         `json:"size"`
	IsDir        bool                          `json:"is_dir"`
	Modified     time.Time                     `json:"modified"`
	Created      time.Time                     `json:"created"`
	Sign         string                        `json:"sign"`
	Thumb        string                        `json:"thumb"`
	Type         int                           `json:"type"`
	HashInfoStr  string                        `json:"hashinfo"`
	HashInfo     map[*utils.HashType]string    `json:"hash_info"`
	MountDetails *model.StorageDetailsWithName `json:"mount_details,omitempty"`
}

type FsListResp struct {
	Content  []ObjResp `json:"content"`
	Total    int64     `json:"total"`
	Readme   string    `json:"readme"`
	Header   string    `json:"header"`
	Write    bool      `json:"write"`
	Provider string    `json:"provider"`
}

func FsListSplit(c *gin.Context) {
	var req ListReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	req.Validate()
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if req.Refresh && !user.IsAdmin() {
		common.ErrorStrResp(c, "Refresh without permission", 403)
		return
	}
	if strings.HasPrefix(req.Path, "/@s") {
		req.Path = strings.TrimPrefix(req.Path, "/@s")
		SharingList(c, &req)
		return
	}
	if user.IsGuest() && user.Disabled {
		common.ErrorStrResp(c, "Guest user is disabled, login please", 401)
		return
	}
	FsList(c, &req, user)
}

func FsList(c *gin.Context, req *ListReq, user *model.User) {
	reqPath, err := user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	meta, err := op.GetNearestMeta(reqPath)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorResp(c, err, 500, true)
			return
		}
	}
	common.GinWithValue(c, conf.MetaKey, meta)
	if !common.CanAccess(user, meta, reqPath, req.Password) {
		common.ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return
	}
	if !user.CanWrite() && !common.CanWrite(meta, reqPath) && req.Refresh {
		common.ErrorStrResp(c, "Refresh without permission", 403)
		return
	}
	objs, err := fs.List(c.Request.Context(), reqPath, &fs.ListArgs{
		Refresh:            req.Refresh,
		WithStorageDetails: !user.IsGuest() && !setting.GetBool(conf.HideStorageDetails),
	})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	total, objs := pagination(objs, &req.PageReq)
	provider := "unknown"
	storage, err := fs.GetStorage(reqPath, &fs.GetStoragesArgs{})
	if err == nil {
		provider = storage.GetStorage().Driver
	}
	common.SuccessResp(c, FsListResp{
		Content:  toObjsResp(objs, reqPath, isEncrypt(meta, reqPath)),
		Total:    int64(total),
		Readme:   getReadme(meta, reqPath),
		Header:   getHeader(meta, reqPath),
		Write:    user.CanWrite() || common.CanWrite(meta, reqPath),
		Provider: provider,
	})
}

func FsDirs(c *gin.Context) {
	var req DirReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	reqPath := req.Path
	if req.ForceRoot {
		if !user.IsAdmin() {
			common.ErrorStrResp(c, "Permission denied", 403)
			return
		}
	} else {
		tmp, err := user.JoinPath(req.Path)
		if err != nil {
			common.ErrorResp(c, err, 403)
			return
		}
		reqPath = tmp
	}
	meta, err := op.GetNearestMeta(reqPath)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorResp(c, err, 500, true)
			return
		}
	}
	common.GinWithValue(c, conf.MetaKey, meta)
	if !common.CanAccess(user, meta, reqPath, req.Password) {
		common.ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return
	}
	objs, err := fs.List(c.Request.Context(), reqPath, &fs.ListArgs{})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	dirs := filterDirs(objs)
	common.SuccessResp(c, dirs)
}

type DirResp struct {
	Name     string    `json:"name"`
	Modified time.Time `json:"modified"`
}

func filterDirs(objs []model.Obj) []DirResp {
	var dirs []DirResp
	for _, obj := range objs {
		if obj.IsDir() {
			dirs = append(dirs, DirResp{
				Name:     obj.GetName(),
				Modified: obj.ModTime(),
			})
		}
	}
	return dirs
}

func getReadme(meta *model.Meta, path string) string {
	if meta != nil && (utils.PathEqual(meta.Path, path) || meta.RSub) {
		return meta.Readme
	}
	return ""
}

func getHeader(meta *model.Meta, path string) string {
	if meta != nil && (utils.PathEqual(meta.Path, path) || meta.HeaderSub) {
		return meta.Header
	}
	return ""
}

func isEncrypt(meta *model.Meta, path string) bool {
	if common.IsStorageSignEnabled(path) {
		return true
	}
	if meta == nil || meta.Password == "" {
		return false
	}
	if !utils.PathEqual(meta.Path, path) && !meta.PSub {
		return false
	}
	return true
}

func isEncryptForRequest(ctx context.Context, meta *model.Meta, path string) bool {
	if common.IsStorageSignEnabledForRequest(ctx, path) {
		return true
	}
	if meta == nil || meta.Password == "" {
		return false
	}
	if !utils.PathEqual(meta.Path, path) && !meta.PSub {
		return false
	}
	return true
}

func pagination(objs []model.Obj, req *model.PageReq) (int, []model.Obj) {
	pageIndex, pageSize := req.Page, req.PerPage
	total := len(objs)
	start := (pageIndex - 1) * pageSize
	if start > total {
		return total, []model.Obj{}
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return total, objs[start:end]
}

func toObjsResp(objs []model.Obj, parent string, encrypt bool) []ObjResp {
	var resp []ObjResp
	for _, obj := range objs {
		thumb, _ := model.GetThumb(obj)
		mountDetails, _ := model.GetStorageDetails(obj)
		resp = append(resp, ObjResp{
			Id:           obj.GetID(),
			Path:         obj.GetPath(),
			Name:         obj.GetName(),
			Size:         obj.GetSize(),
			IsDir:        obj.IsDir(),
			Modified:     obj.ModTime(),
			Created:      obj.CreateTime(),
			HashInfoStr:  obj.GetHash().String(),
			HashInfo:     obj.GetHash().Export(),
			Sign:         common.Sign(obj, parent, encrypt),
			Thumb:        thumb,
			Type:         utils.GetObjType(obj.GetName(), obj.IsDir()),
			MountDetails: mountDetails,
		})
	}
	return resp
}

type FsGetReq struct {
	Path     string `json:"path" form:"path"`
	Password string `json:"password" form:"password"`
}

type FsGetResp struct {
	ObjResp
	RawURL   string    `json:"raw_url"`
	Readme   string    `json:"readme"`
	Header   string    `json:"header"`
	Provider string    `json:"provider"`
	Related  []ObjResp `json:"related"`
}

func FsGetSplit(c *gin.Context) {
	var req FsGetReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	if strings.HasPrefix(req.Path, "/@s") {
		req.Path = strings.TrimPrefix(req.Path, "/@s")
		SharingGet(c, &req)
		return
	}
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	if user.IsGuest() && user.Disabled {
		common.ErrorStrResp(c, "Guest user is disabled, login please", 401)
		return
	}
	FsGet(c, &req, user)
}

func FsGet(c *gin.Context, req *FsGetReq, user *model.User) {
	reqPath, err := user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	meta, err := op.GetNearestMeta(reqPath)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorResp(c, err, 500)
			return
		}
	}
	common.GinWithValue(c, conf.MetaKey, meta)
	if !common.CanAccess(user, meta, reqPath, req.Password) {
		common.ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return
	}
	ctx := op.EnsureLinkAPIBalanceStateForRequest(c.Request.Context())
	obj, err := fs.Get(ctx, reqPath, &fs.GetArgs{
		WithStorageDetails: !user.IsGuest() && !setting.GetBool(conf.HideStorageDetails),
	})
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	var rawURL string

	storage, err := fs.GetStorageWithContext(ctx, reqPath, &fs.GetStoragesArgs{})
	provider, ok := model.GetProvider(obj)
	if !ok && err == nil {
		provider = storage.Config().Name
	}
	if !obj.IsDir() {
		if err != nil {
			common.ErrorResp(c, err, 500)
			return
		}
		route, err := op.ResolveWebDownloadRoute(ctx, reqPath)
		if err != nil {
			common.ErrorResp(c, err, 500)
			return
		}
		switch route.EffectivePolicy {
		case op.WebDownloadProxyURL:
			rawURL, err = op.WebDownloadExternalProxyURL(route)
			if err != nil {
				common.ErrorResp(c, err, 500)
				return
			}
		case op.WebDownloadNativeProxy:
			needSign, err := common.IsPathSignRequired(route.PolicyOwnerRawPath)
			if err != nil {
				common.ErrorResp(c, err, 500)
				return
			}
			rawURL, err = op.WebDownloadCanonicalProxyURL(common.GetApiUrl(c.Request.Context()), route, webDownloadTypeQuery(c), needSign)
			if err != nil {
				common.ErrorResp(c, err, 500)
				return
			}
		case op.WebDownloadRedirect302:
			link, _, err := op.WebDownloadLeafDirectLink(ctx, route, model.LinkArgs{
				IP:       c.ClientIP(),
				Header:   c.Request.Header,
				Type:     c.Query("type"),
				Redirect: true,
			})
			if err != nil {
				common.ErrorResp(c, err, 500)
				return
			}
			defer link.Close()
			rawURL = link.URL
		default:
			common.ErrorResp(c, fmt.Errorf("unsupported web download policy %q", route.EffectivePolicy), 500)
			return
		}
	}
	var related []model.Obj
	parentPath := stdpath.Dir(reqPath)
	sameLevelFiles, err := fs.List(ctx, parentPath, &fs.ListArgs{})
	if err == nil {
		related = filterRelated(sameLevelFiles, obj)
	}
	parentMeta, _ := op.GetNearestMeta(parentPath)
	currentEncrypt := isEncryptForRequest(ctx, meta, reqPath)
	parentEncrypt := isEncryptForRequest(ctx, parentMeta, parentPath)
	thumb, _ := model.GetThumb(obj)
	mountDetails, _ := model.GetStorageDetails(obj)
	common.SuccessResp(c, FsGetResp{
		ObjResp: ObjResp{
			Id:           obj.GetID(),
			Path:         obj.GetPath(),
			Name:         obj.GetName(),
			Size:         obj.GetSize(),
			IsDir:        obj.IsDir(),
			Modified:     obj.ModTime(),
			Created:      obj.CreateTime(),
			HashInfoStr:  obj.GetHash().String(),
			HashInfo:     obj.GetHash().Export(),
			Sign:         common.Sign(obj, parentPath, currentEncrypt),
			Type:         utils.GetFileType(obj.GetName()),
			Thumb:        thumb,
			MountDetails: mountDetails,
		},
		RawURL:   rawURL,
		Readme:   getReadme(meta, reqPath),
		Header:   getHeader(meta, reqPath),
		Provider: provider,
		Related:  toObjsResp(related, parentPath, parentEncrypt),
	})
}

func filterRelated(objs []model.Obj, obj model.Obj) []model.Obj {
	var related []model.Obj
	nameWithoutExt := strings.TrimSuffix(obj.GetName(), stdpath.Ext(obj.GetName()))
	for _, o := range objs {
		if o.GetName() == obj.GetName() {
			continue
		}
		if strings.HasPrefix(o.GetName(), nameWithoutExt) {
			related = append(related, o)
		}
	}
	return related
}

type FsOtherReq struct {
	model.FsOtherArgs
	Password string `json:"password" form:"password"`
}

func FsOther(c *gin.Context) {
	var req FsOtherReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user := c.Request.Context().Value(conf.UserKey).(*model.User)
	var err error
	req.Path, err = user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	meta, err := op.GetNearestMeta(req.Path)
	if err != nil {
		if !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorResp(c, err, 500)
			return
		}
	}
	common.GinWithValue(c, conf.MetaKey, meta)
	if !common.CanAccess(user, meta, req.Path, req.Password) {
		common.ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return
	}
	res, err := fs.Other(c.Request.Context(), req.FsOtherArgs)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}
	common.SuccessResp(c, res)
}
