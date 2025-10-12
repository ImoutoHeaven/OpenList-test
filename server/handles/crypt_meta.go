package handles

import (
	"encoding/base64"
	"net/http"
	stdpath "path"
	"strings"

	driverCrypt "github.com/OpenListTeam/OpenList/v4/drivers/crypt"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

type cryptRemoteInfo struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	Concurrency int               `json:"concurrency,omitempty"`
	PartSize    int               `json:"part_size,omitempty"`
}

type cryptMetaResponse struct {
	Path                string          `json:"path"`
	FileName            string          `json:"file_name"`
	Size                int64           `json:"size"`
	EncryptedSize       int64           `json:"encrypted_size"`
	FileHeaderSize      int             `json:"file_header_size"`
	BlockDataSize       int             `json:"block_data_size"`
	BlockHeaderSize     int             `json:"block_header_size"`
	DataKey             string          `json:"data_key"`
	EncryptedSuffix     string          `json:"encrypted_suffix"`
	EncryptedPath       string          `json:"encrypted_path"`
	EncryptedActualPath string          `json:"encrypted_actual_path"`
	Remote              cryptRemoteInfo `json:"remote"`
}

func CryptMeta(c *gin.Context) {
	var req MkdirOrLinkReq
	if err := c.ShouldBind(&req); err != nil {
		common.ErrorResp(c, err, http.StatusBadRequest)
		return
	}
	storage, err := fs.GetStorage(req.Path, &fs.GetStoragesArgs{})
	if err != nil {
		common.ErrorResp(c, err, http.StatusInternalServerError)
		return
	}

	cryptDriver, ok := storage.(*driverCrypt.Crypt)
	if !ok {
		common.ErrorStrResp(c, "storage is not crypt", http.StatusBadRequest)
		return
	}

	cleanPath := utils.FixAndCleanPath(req.Path)
	dirPath := stdpath.Dir(cleanPath)
	if dirPath == "." {
		dirPath = "/"
	}
	fileName := stdpath.Base(cleanPath)
	listEntries, err := fs.List(c.Request.Context(), dirPath, &fs.ListArgs{})
	if err != nil {
		common.ErrorResp(c, err, http.StatusInternalServerError)
		return
	}

	var obj model.Obj
	for _, entry := range listEntries {
		if entry.GetName() == fileName {
			obj = entry
			break
		}
	}
	if obj == nil {
		common.ErrorStrResp(c, "object not found", http.StatusNotFound)
		return
	}
	if obj.IsDir() {
		common.ErrorStrResp(c, "directory is not supported", http.StatusBadRequest)
		return
	}

	dataKey, err := cryptDriver.DataKey()
	if err != nil {
		common.ErrorResp(c, err, http.StatusInternalServerError)
		return
	}

	linkArgs := model.LinkArgs{
		IP:     c.ClientIP(),
		Header: c.Request.Header.Clone(),
	}

	relativePath := strings.TrimPrefix(cleanPath, storage.GetStorage().MountPath)
	relativePath = strings.TrimPrefix(relativePath, "/")

	encryptedPath := cryptDriver.EncryptedPath(relativePath, false)
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(encryptedPath)
	if err != nil {
		common.ErrorResp(c, err, http.StatusInternalServerError)
		return
	}
	remoteLink, remoteObj, err := op.Link(c.Request.Context(), remoteStorage, remoteActualPath, linkArgs)
	if err != nil {
		common.ErrorResp(c, err, http.StatusInternalServerError)
		return
	}
	defer remoteLink.Close()

	var encryptedSize int64
	if remoteLink.ContentLength > 0 {
		encryptedSize = remoteLink.ContentLength
	} else if remoteObj != nil {
		encryptedSize = remoteObj.GetSize()
	}

	headerMap := make(map[string]string, len(remoteLink.Header))
	for k, v := range remoteLink.Header {
		headerMap[k] = strings.Join(v, ",")
	}

	actualPath := remoteActualPath

	resp := cryptMetaResponse{
		Path:                cleanPath,
		FileName:            obj.GetName(),
		Size:                obj.GetSize(),
		EncryptedSize:       encryptedSize,
		FileHeaderSize:      driverCrypt.FileHeaderSize,
		BlockDataSize:       driverCrypt.DataBlockSize,
		BlockHeaderSize:     driverCrypt.DataBlockHeaderSize,
		DataKey:             base64.StdEncoding.EncodeToString(dataKey),
		EncryptedSuffix:     cryptDriver.EncryptedSuffix,
		EncryptedPath:       encryptedPath,
		EncryptedActualPath: actualPath,
		Remote: cryptRemoteInfo{
			URL:         remoteLink.URL,
			Method:      http.MethodGet,
			Headers:     headerMap,
			Concurrency: remoteLink.Concurrency,
			PartSize:    remoteLink.PartSize,
		},
	}

	common.SuccessResp(c, resp)
}
