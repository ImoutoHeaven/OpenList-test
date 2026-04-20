package google_drive

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/go-resty/resty/v2"
)

type GoogleDrive struct {
	model.Storage
	Addition
	AccessToken            string
	ServiceAccountFile     int
	ServiceAccountFileList []string
	modeCfg                downloadModeConfig
	accounts               []accountRuntime
	accountPool            *accountPool
	accountStore           accountStore
	accountStateMu         sync.RWMutex
	accountRefreshSlots    []*sync.Mutex
	accountRefreshMu       sync.Mutex
	accountRefreshWG       sync.WaitGroup
	accountRefreshClosed   bool
}

func (d *GoogleDrive) Config() driver.Config {
	return config
}

func (d *GoogleDrive) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *GoogleDrive) Init(ctx context.Context) error {
	if d.ChunkSize == 0 {
		d.ChunkSize = 5
	}

	cfg, err := validateDownloadModeConfig(d.Addition)
	if err != nil {
		return err
	}
	d.modeCfg = cfg

	if !cfg.Enabled {
		if strings.TrimSpace(d.RefreshToken) == "" {
			return fmt.Errorf("google_drive: refresh_token is required in single-account mode")
		}
		return d.refreshToken()
	}

	return d.initAccountsJSONMode(ctx)
}

func (d *GoogleDrive) Drop(ctx context.Context) error {
	if !d.modeCfg.Enabled || d.accountStore == nil {
		return nil
	}
	d.stopAccountRefreshes()
	waitErr := d.waitForAccountRefreshes(ctx)
	flushErr := d.accountStore.flush(ctx)
	shutdownErr := d.accountStore.shutdown(ctx)
	if waitErr != nil {
		return waitErr
	}
	if flushErr != nil {
		return flushErr
	}
	return shutdownErr
}

func (d *GoogleDrive) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	files, err := d.getFiles(dir.GetID())
	if err != nil {
		return nil, err
	}
	return utils.SliceConvert(files, func(src File) (model.Obj, error) {
		return fileToObj(src), nil
	})
}

func (d *GoogleDrive) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	url := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?includeItemsFromAllDrives=true&supportsAllDrives=true", file.GetID())
	authorizationToken := d.currentAccessToken()
	if d.modeCfg.Enabled {
		winningToken, _, err := d.requestDownloadWithRotation(ctx, url, http.MethodGet, nil, nil)
		if err != nil {
			return nil, err
		}
		authorizationToken = winningToken
	} else {
		_, err := d.request(url, http.MethodGet, nil, nil)
		if err != nil {
			return nil, err
		}
		authorizationToken = d.currentAccessToken()
	}
	link := model.Link{
		URL: url + "&alt=media&acknowledgeAbuse=true",
		Header: http.Header{
			"Authorization": []string{"Bearer " + authorizationToken},
		},
	}
	return &link, nil
}

func (d *GoogleDrive) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	data := base.Json{
		"name":     dirName,
		"parents":  []string{parentDir.GetID()},
		"mimeType": "application/vnd.google-apps.folder",
	}
	_, err := d.request("https://www.googleapis.com/drive/v3/files", http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
	}, nil)
	return err
}

func (d *GoogleDrive) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	query := map[string]string{
		"addParents":    dstDir.GetID(),
		"removeParents": "root",
	}
	url := "https://www.googleapis.com/drive/v3/files/" + srcObj.GetID()
	_, err := d.request(url, http.MethodPatch, func(req *resty.Request) {
		req.SetQueryParams(query)
	}, nil)
	return err
}

func (d *GoogleDrive) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	data := base.Json{
		"name": newName,
	}
	url := "https://www.googleapis.com/drive/v3/files/" + srcObj.GetID()
	_, err := d.request(url, http.MethodPatch, func(req *resty.Request) {
		req.SetBody(data)
	}, nil)
	return err
}

func (d *GoogleDrive) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	return errs.NotSupport
}

func (d *GoogleDrive) Remove(ctx context.Context, obj model.Obj) error {
	url := "https://www.googleapis.com/drive/v3/files/" + obj.GetID()
	_, err := d.request(url, http.MethodDelete, nil, nil)
	return err
}

func (d *GoogleDrive) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	obj := stream.GetExist()
	var (
		e    Error
		url  string
		data base.Json
		res  *resty.Response
		err  error
	)
	accessToken := d.currentAccessToken()
	if d.modeCfg.Enabled {
		accessToken, err = d.primaryAccessToken()
		if err != nil {
			return err
		}
	}
	if obj != nil {
		url = fmt.Sprintf("https://www.googleapis.com/upload/drive/v3/files/%s?uploadType=resumable&supportsAllDrives=true", obj.GetID())
		data = base.Json{}
	} else {
		data = base.Json{
			"name":    stream.GetName(),
			"parents": []string{dstDir.GetID()},
		}
		url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true"
	}
	req := base.NoRedirectClient.R().
		SetHeaders(map[string]string{
			"Authorization":           "Bearer " + accessToken,
			"X-Upload-Content-Type":   stream.GetMimetype(),
			"X-Upload-Content-Length": strconv.FormatInt(stream.GetSize(), 10),
		}).
		SetError(&e).SetBody(data).SetContext(ctx)
	if obj != nil {
		res, err = req.Patch(url)
	} else {
		res, err = req.Post(url)
	}
	if err != nil {
		return err
	}
	if e.Error.Code != 0 {
		if e.Error.Code == 401 {
			if d.modeCfg.Enabled {
				err = d.refreshPrimaryAccount(ctx)
				if err != nil {
					return err
				}
				return d.Put(ctx, dstDir, stream, up)
			}
			err = d.refreshToken()
			if err != nil {
				return err
			}
			return d.Put(ctx, dstDir, stream, up)
		}
		return fmt.Errorf("%s: %v", e.Error.Message, e.Error.Errors)
	}
	putUrl := res.Header().Get("location")
	if stream.GetSize() < d.ChunkSize*1024*1024 {
		err = d.smallFileUpload(ctx, stream, putUrl)
	} else {
		err = d.chunkUpload(ctx, stream, putUrl, up)
	}
	return err
}

func (d *GoogleDrive) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	if d.DisableDiskUsage {
		return nil, errs.NotImplement
	}
	about, err := d.getAbout(ctx)
	if err != nil {
		return nil, err
	}
	var total, used uint64
	if about.StorageQuota.Limit == nil {
		total = 0
	} else {
		total, err = strconv.ParseUint(*about.StorageQuota.Limit, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	used, err = strconv.ParseUint(about.StorageQuota.Usage, 10, 64)
	if err != nil {
		return nil, err
	}
	return &model.StorageDetails{
		DiskUsage: *model.NewDiskUsageFromUsedAndTotal(used, total),
	}, nil
}

var _ driver.Driver = (*GoogleDrive)(nil)
