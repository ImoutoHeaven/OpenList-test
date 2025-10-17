package handles

import (
	"encoding/base64"
	"net/http"
	stdpath "path"
	"strings"

	driverCrypt "github.com/OpenListTeam/OpenList/v4/drivers/crypt"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

type cryptRemoteInfo struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	Concurrency int               `json:"concurrency,omitempty"`
	PartSize    int               `json:"part_size,omitempty"`
	RawPath     string            `json:"raw_path,omitempty"`
}

type cryptMetaResponse struct {
	Mode                string          `json:"mode"`
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

type storageChainNode struct {
	storage    driver.Driver
	rawPath    string
	actualPath string
}

type aliasPathResolver interface {
	ResolveRawPaths(path string) []string
}

func buildStorageChain(rawPath string) ([]storageChainNode, error) {
	const maxDepth = 16
	cleaned := utils.FixAndCleanPath(rawPath)
	nodes := make([]storageChainNode, 0, 4)
	currentRawPath := cleaned
	visited := make(map[string]struct{})

	for depth := 0; depth < maxDepth; depth++ {
		storage, actualPath, err := op.GetStorageAndActualPath(currentRawPath)
		if err != nil {
			return nil, err
		}
		key := storage.GetStorage().MountPath + ":" + actualPath
		if _, ok := visited[key]; ok {
			break
		}
		visited[key] = struct{}{}
		nodes = append(nodes, storageChainNode{
			storage:    storage,
			rawPath:    currentRawPath,
			actualPath: actualPath,
		})

		resolver, ok := storage.(aliasPathResolver)
		if !ok {
			break
		}
		candidates := resolver.ResolveRawPaths(actualPath)
		if len(candidates) == 0 {
			break
		}
		next := utils.FixAndCleanPath(candidates[0])
		if next == currentRawPath {
			break
		}
		currentRawPath = next
	}

	return nodes, nil
}

func pickNestedProxyURL(nodes []storageChainNode) string {
	if len(nodes) == 0 {
		return ""
	}
	candidates := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if url := common.GenerateDownProxyURL(node.storage.GetStorage(), node.rawPath); url != "" {
			candidates = append(candidates, url)
		}
	}
	if len(candidates) >= 2 {
		return candidates[1]
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
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

	linkArgs := model.LinkArgs{
		IP:     c.ClientIP(),
		Header: c.Request.Header.Clone(),
	}

	mode := "plain"
	var (
		fileHeaderSize   int
		blockDataSize    int
		blockHeaderSize  int
		dataKeyEncoded   string
		encryptedSuffix  string
		requestPath      string
		remoteStorage    driver.Driver
		remoteActualPath string
		encryptionPath   string
		encryptionActual string
	)

	var storageChain []storageChainNode

	if cryptDriver, ok := storage.(*driverCrypt.Crypt); ok {
		mode = "crypt"
		dataKey, err := cryptDriver.DataKey()
		if err != nil {
			common.ErrorResp(c, err, http.StatusInternalServerError)
			return
		}
		dataKeyEncoded = base64.StdEncoding.EncodeToString(dataKey)
		relativePath := strings.TrimPrefix(cleanPath, storage.GetStorage().MountPath)
		relativePath = strings.TrimPrefix(relativePath, "/")
		requestPath = cryptDriver.EncryptedPath(relativePath, false)
		fileHeaderSize = driverCrypt.FileHeaderSize
		blockDataSize = driverCrypt.DataBlockSize
		blockHeaderSize = driverCrypt.DataBlockHeaderSize
		encryptedSuffix = cryptDriver.EncryptedSuffix
		remoteStorage, remoteActualPath, err = op.GetStorageAndActualPath(requestPath)
		if err != nil {
			common.ErrorResp(c, errors.Wrapf(err, "failed to locate remote storage for %s", requestPath), http.StatusInternalServerError)
			return
		}
		storageChain, err = buildStorageChain(requestPath)
		if err != nil {
			common.ErrorResp(c, errors.Wrapf(err, "failed to resolve storage chain for %s", requestPath), http.StatusInternalServerError)
			return
		}
		if len(storageChain) > 0 {
			last := storageChain[len(storageChain)-1]
			remoteStorage = last.storage
			remoteActualPath = last.actualPath
		}
		encryptionPath = requestPath
		encryptionActual = remoteActualPath
	} else {
		requestPath = cleanPath
		remoteStorage, remoteActualPath, err = op.GetStorageAndActualPath(requestPath)
		if err != nil {
			common.ErrorResp(c, errors.Wrapf(err, "failed to locate storage for %s", requestPath), http.StatusInternalServerError)
			return
		}
		storageChain, err = buildStorageChain(requestPath)
		if err != nil {
			common.ErrorResp(c, errors.Wrapf(err, "failed to resolve storage chain for %s", requestPath), http.StatusInternalServerError)
			return
		}
		if len(storageChain) > 0 {
			last := storageChain[len(storageChain)-1]
			remoteStorage = last.storage
			remoteActualPath = last.actualPath
		}
		encryptionPath = requestPath
		encryptionActual = remoteActualPath
	}

	remoteLink, remoteObj, err := op.Link(c.Request.Context(), remoteStorage, remoteActualPath, linkArgs)
	if err != nil {
		common.ErrorResp(c, errors.Wrapf(err, "failed to get remote link for %s", remoteActualPath), http.StatusInternalServerError)
		return
	}
	defer remoteLink.Close()

	useProxy := false
	remoteURL := remoteLink.URL
	selectedProxy := pickNestedProxyURL(storageChain)
	if selectedProxy != "" {
		useProxy = true
		remoteURL = selectedProxy
	} else if proxyURL := common.GenerateDownProxyURL(remoteStorage.GetStorage(), encryptionPath); proxyURL != "" {
		useProxy = true
		remoteURL = proxyURL
	} else if remoteStorage.Config().MustProxy() || remoteStorage.GetStorage().WebProxy {
		useProxy = true
		proxyURL := common.GetApiUrl(c) + "/p" + utils.EncodePath(encryptionPath, true)
		if common.IsStorageSignEnabled(encryptionPath) || setting.GetBool(conf.SignAll) {
			proxyURL += "?sign=" + sign.Sign(encryptionPath)
		}
		remoteURL = proxyURL
	}

	var encryptedSize int64
	if remoteLink.ContentLength > 0 {
		encryptedSize = remoteLink.ContentLength
	} else if remoteObj != nil {
		encryptedSize = remoteObj.GetSize()
	}

	var headerMap map[string]string
	if !useProxy {
		headerMap = make(map[string]string, len(remoteLink.Header))
		for k, v := range remoteLink.Header {
			headerMap[k] = strings.Join(v, ",")
		}
	}

	actualPath := remoteActualPath
	concurrency := remoteLink.Concurrency
	partSize := remoteLink.PartSize
	if useProxy {
		concurrency = 0
		partSize = 0
	} else if concurrency > 16 {
		concurrency = 16
	}

	resp := cryptMetaResponse{
		Mode:                mode,
		Path:                cleanPath,
		FileName:            obj.GetName(),
		Size:                obj.GetSize(),
		EncryptedSize:       encryptedSize,
		FileHeaderSize:      fileHeaderSize,
		BlockDataSize:       blockDataSize,
		BlockHeaderSize:     blockHeaderSize,
		DataKey:             dataKeyEncoded,
		EncryptedSuffix:     encryptedSuffix,
		EncryptedPath:       encryptionPath,
		EncryptedActualPath: encryptionActual,
		Remote: cryptRemoteInfo{
			URL:         remoteURL,
			Method:      http.MethodGet,
			Headers:     headerMap,
			Concurrency: concurrency,
			PartSize:    partSize,
			RawPath:     actualPath,
		},
	}

	common.SuccessResp(c, resp)
}
