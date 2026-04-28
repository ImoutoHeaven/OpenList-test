package google_drive

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"golang.org/x/oauth2"
)

type downloadModeConfig struct {
	Enabled          bool
	AccountsPath     string
	SelectionPolicy  string
	DownloadRetryMax int
}

type oauthTokenView struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry,omitempty"`
}

type accountConfig struct {
	Index               int
	Name                string
	ClientID            string
	ClientSecret        string
	PersistClientID     string
	PersistClientSecret string
	TokenJSON           string
}

type accountRuntime struct {
	Index        int
	Name         string
	ClientID     string
	ClientSecret string
	TokenJSON    string
	Token        oauthTokenView
}

type accountPool struct {
	mu         sync.Mutex
	policy     string
	rrCursor   uint64
	accounts   []accountRuntime
	randMu     sync.Mutex
	randSource *rand.Rand
}

type accountSnapshot struct {
	Index        int
	Name         string
	ClientID     string
	ClientSecret string
	TokenJSON    string
	Token        oauthTokenView
}

type accountStore interface {
	setToken(index int, tokenJSON string)
	flush(ctx context.Context) error
	shutdown(ctx context.Context) error
}

type noopAccountStore struct{}

func (noopAccountStore) setToken(int, string) {}

func (noopAccountStore) flush(context.Context) error { return nil }

func (noopAccountStore) shutdown(context.Context) error { return nil }

type rawAccountConfig struct {
	Name         string          `json:"name"`
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	Token        json.RawMessage `json:"token"`
}

func validateDownloadModeConfig(add Addition) (downloadModeConfig, error) {
	policy := strings.TrimSpace(add.AccountSelectionPolicy)
	if policy == "" {
		policy = "round_robin"
	}
	if policy != "round_robin" && policy != "random" {
		return downloadModeConfig{}, fmt.Errorf("google_drive: account_selection_policy must be one of round_robin,random")
	}

	retryMax := 2
	if add.DownloadRetryMax != nil {
		retryMax = *add.DownloadRetryMax
	}
	if retryMax < 0 {
		return downloadModeConfig{}, fmt.Errorf("google_drive: download_retry_max must be >= 0")
	}

	path := strings.TrimSpace(add.AccountsJSON)
	if path == "" {
		return downloadModeConfig{}, nil
	}
	if !filepath.IsAbs(path) {
		return downloadModeConfig{}, fmt.Errorf("google_drive: accounts_json must be an absolute path")
	}

	return downloadModeConfig{
		Enabled:          true,
		AccountsPath:     path,
		SelectionPolicy:  policy,
		DownloadRetryMax: retryMax,
	}, nil
}

func parseAccountsJSON(path string, add Addition) ([]accountConfig, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("google_drive: accounts_json must be an absolute path")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("google_drive: read accounts_json: %w", err)
	}

	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return nil, fmt.Errorf("google_drive: accounts_json must not be empty")
	}

	var rawEntries []rawAccountConfig
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &rawEntries); err != nil {
			return nil, fmt.Errorf("google_drive: parse accounts_json: %w", err)
		}
	} else {
		lines := strings.Split(trimmed, "\n")
		rawEntries = make([]rawAccountConfig, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var entry rawAccountConfig
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				return nil, fmt.Errorf("google_drive: parse accounts_json: %w", err)
			}
			rawEntries = append(rawEntries, entry)
		}
	}

	if len(rawEntries) == 0 {
		return nil, fmt.Errorf("google_drive: accounts_json must not be empty")
	}

	accounts := make([]accountConfig, 0, len(rawEntries))
	for index, entry := range rawEntries {
		tokenJSON, err := normalizeAccountTokenJSON(entry.Token)
		if err != nil {
			return nil, err
		}

		name := strings.TrimSpace(entry.Name)
		if name == "" {
			name = fmt.Sprintf("account-%d", index)
		}

		clientID := strings.TrimSpace(entry.ClientID)
		if clientID == "" {
			clientID = add.ClientID
		}

		clientSecret := strings.TrimSpace(entry.ClientSecret)
		if clientSecret == "" {
			clientSecret = add.ClientSecret
		}

		accounts = append(accounts, accountConfig{
			Index:               index,
			Name:                name,
			ClientID:            clientID,
			ClientSecret:        clientSecret,
			PersistClientID:     strings.TrimSpace(entry.ClientID),
			PersistClientSecret: strings.TrimSpace(entry.ClientSecret),
			TokenJSON:           tokenJSON,
		})
	}

	return accounts, nil
}

func normalizeAccountTokenJSON(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", fmt.Errorf("google_drive: token must be a JSON object")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return "", fmt.Errorf("google_drive: token must be a JSON object")
	}

	var tokenMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &tokenMap); err != nil {
		return "", fmt.Errorf("google_drive: token must be a JSON object")
	}

	normalized, err := json.Marshal(tokenMap)
	if err != nil {
		return "", fmt.Errorf("google_drive: normalize token JSON: %w", err)
	}

	var token oauth2.Token
	if err := json.Unmarshal(normalized, &token); err != nil {
		return "", fmt.Errorf("google_drive: token must be parseable OAuth token JSON: %w", err)
	}
	if strings.TrimSpace(token.AccessToken) == "" && strings.TrimSpace(token.RefreshToken) == "" {
		return "", fmt.Errorf("google_drive: token must include access_token or refresh_token")
	}

	return string(normalized), nil
}

func initAccountRuntime(cfg accountConfig) (accountRuntime, error) {
	var token oauthTokenView
	if err := json.Unmarshal([]byte(cfg.TokenJSON), &token); err != nil {
		return accountRuntime{}, fmt.Errorf("google_drive: token must be parseable OAuth token JSON: %w", err)
	}

	return accountRuntime{
		Index:        cfg.Index,
		Name:         cfg.Name,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenJSON:    cfg.TokenJSON,
		Token:        token,
	}, nil
}

func newAccountPool(policy string, accounts []accountRuntime) *accountPool {
	pooled := make([]accountRuntime, len(accounts))
	copy(pooled, accounts)
	return &accountPool{
		policy:     policy,
		accounts:   pooled,
		randSource: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (p *accountPool) nextAttemptOrder(attemptBudget int) []int {
	if p == nil || len(p.accounts) == 0 || attemptBudget <= 0 {
		return nil
	}
	if attemptBudget > len(p.accounts) {
		attemptBudget = len(p.accounts)
	}

	if p.policy == "random" {
		indexes := make([]int, len(p.accounts))
		for i := range indexes {
			indexes[i] = i
		}
		p.randMu.Lock()
		p.randSource.Shuffle(len(indexes), func(i, j int) {
			indexes[i], indexes[j] = indexes[j], indexes[i]
		})
		p.randMu.Unlock()
		return indexes[:attemptBudget]
	}

	start := int(atomic.AddUint64(&p.rrCursor, 1)-1) % len(p.accounts)
	order := make([]int, 0, attemptBudget)
	for i := 0; i < attemptBudget; i++ {
		order = append(order, (start+i)%len(p.accounts))
	}
	return order
}

func (d *GoogleDrive) syncPrimaryAccessToken() error {
	d.accountStateMu.Lock()
	defer d.accountStateMu.Unlock()
	if len(d.accounts) == 0 {
		return fmt.Errorf("google_drive: accounts_json must include at least one account")
	}
	d.AccessToken = d.accounts[0].Token.AccessToken
	return nil
}

func (d *GoogleDrive) currentAccessToken() string {
	d.accountStateMu.RLock()
	defer d.accountStateMu.RUnlock()
	return d.AccessToken
}

func (d *GoogleDrive) setAccessToken(accessToken string) {
	d.accountStateMu.Lock()
	d.AccessToken = accessToken
	d.accountStateMu.Unlock()
}

func (d *GoogleDrive) primaryAccessToken() (string, error) {
	d.accountStateMu.RLock()
	defer d.accountStateMu.RUnlock()
	if len(d.accounts) == 0 {
		return "", fmt.Errorf("google_drive: accounts_json must include at least one account")
	}
	return d.accounts[0].Token.AccessToken, nil
}

func (d *GoogleDrive) accountSnapshot(index int) (accountSnapshot, error) {
	d.accountStateMu.RLock()
	defer d.accountStateMu.RUnlock()
	if index < 0 || index >= len(d.accounts) {
		return accountSnapshot{}, fmt.Errorf("google_drive: invalid account index %d", index)
	}
	account := d.accounts[index]
	return accountSnapshot{
		Index:        account.Index,
		Name:         account.Name,
		ClientID:     account.ClientID,
		ClientSecret: account.ClientSecret,
		TokenJSON:    account.TokenJSON,
		Token:        account.Token,
	}, nil
}

func (d *GoogleDrive) initAccountsJSONMode(ctx context.Context) error {
	parsed, err := parseAccountsJSON(d.modeCfg.AccountsPath, d.Addition)
	if err != nil {
		return err
	}

	runtimes := make([]accountRuntime, 0, len(parsed))
	for _, cfg := range parsed {
		rt, err := initAccountRuntime(cfg)
		if err != nil {
			return err
		}
		runtimes = append(runtimes, rt)
	}

	d.accountStateMu.Lock()
	d.accounts = runtimes
	d.accountRefreshSlots = make([]*sync.Mutex, len(runtimes))
	for i := range d.accountRefreshSlots {
		d.accountRefreshSlots[i] = &sync.Mutex{}
	}
	d.accountStateMu.Unlock()
	d.accountPool = newAccountPool(d.modeCfg.SelectionPolicy, d.accounts)
	store, err := newAccountStore(parsed, d.modeCfg.AccountsPath)
	if err != nil {
		return err
	}
	d.accountStore = store
	return d.syncPrimaryAccessToken()
}

func (d *GoogleDrive) updateAccountToken(index int, token oauthTokenView) error {
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("google_drive: marshal refreshed token: %w", err)
	}
	d.accountStateMu.Lock()
	if index < 0 || index >= len(d.accounts) {
		d.accountStateMu.Unlock()
		return fmt.Errorf("google_drive: invalid account index %d", index)
	}
	d.accounts[index].Token = token
	d.accounts[index].TokenJSON = string(tokenJSON)
	if index == 0 {
		d.AccessToken = token.AccessToken
	}
	d.accountStateMu.Unlock()
	d.accountStore.setToken(index, string(tokenJSON))
	return nil
}

func (d *GoogleDrive) accountRefreshSlot(index int) (*sync.Mutex, error) {
	d.accountStateMu.Lock()
	defer d.accountStateMu.Unlock()
	if index < 0 || index >= len(d.accounts) {
		return nil, fmt.Errorf("google_drive: invalid account index %d", index)
	}
	if len(d.accountRefreshSlots) != len(d.accounts) {
		slots := make([]*sync.Mutex, len(d.accounts))
		copy(slots, d.accountRefreshSlots)
		for i := range slots {
			if slots[i] == nil {
				slots[i] = &sync.Mutex{}
			}
		}
		d.accountRefreshSlots = slots
	}
	return d.accountRefreshSlots[index], nil
}

func (d *GoogleDrive) beginAccountRefresh() error {
	d.accountRefreshMu.Lock()
	defer d.accountRefreshMu.Unlock()
	if d.accountRefreshClosed {
		return context.Canceled
	}
	d.accountRefreshWG.Add(1)
	return nil
}

func (d *GoogleDrive) endAccountRefresh() {
	d.accountRefreshWG.Done()
}

func (d *GoogleDrive) stopAccountRefreshes() {
	d.accountRefreshMu.Lock()
	d.accountRefreshClosed = true
	d.accountRefreshMu.Unlock()
}

func (d *GoogleDrive) waitForAccountRefreshes(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		d.accountRefreshWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *GoogleDrive) refreshAccount(ctx context.Context, index int) error {
	if err := d.beginAccountRefresh(); err != nil {
		return err
	}
	defer d.endAccountRefresh()
	refreshSlot, err := d.accountRefreshSlot(index)
	if err != nil {
		return err
	}
	refreshSlot.Lock()
	defer refreshSlot.Unlock()
	account, err := d.accountSnapshot(index)
	if err != nil {
		return err
	}
	if d.UseOnlineAPI && len(d.APIAddress) > 0 {
		var resp struct {
			RefreshToken string `json:"refresh_token"`
			AccessToken  string `json:"access_token"`
			ErrorMessage string `json:"text"`
		}
		req := base.RestyClient.R().
			SetHeader("User-Agent", "Mozilla/5.0 (Macintosh; Apple macOS 15_5) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/138.0.0.0 Openlist/425.6.30").
			SetResult(&resp).
			SetQueryParams(map[string]string{
				"refresh_ui": account.Token.RefreshToken,
				"server_use": "true",
				"driver_txt": "googleui_go",
			})
		if ctx != nil {
			req.SetContext(ctx)
		}
		_, err := req.Get(d.APIAddress)
		if err != nil {
			return err
		}
		if resp.RefreshToken == "" || resp.AccessToken == "" {
			if resp.ErrorMessage != "" {
				return fmt.Errorf("failed to refresh token: %s", resp.ErrorMessage)
			}
			return fmt.Errorf("empty token returned from official API, a wrong refresh token may have been used")
		}
		return d.updateAccountToken(index, oauthTokenView{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			Expiry:       account.Token.Expiry,
		})
	}
	if account.ClientID == "" || account.ClientSecret == "" {
		return fmt.Errorf("empty ClientID or ClientSecret")
	}
	url := "https://www.googleapis.com/oauth2/v4/token"
	var resp base.TokenResp
	var e TokenError
	req := base.RestyClient.R().SetResult(&resp).SetError(&e).SetFormData(map[string]string{
		"client_id":     account.ClientID,
		"client_secret": account.ClientSecret,
		"refresh_token": account.Token.RefreshToken,
		"grant_type":    "refresh_token",
	})
	if ctx != nil {
		req.SetContext(ctx)
	}
	_, err = req.Post(url)
	if err != nil {
		return err
	}
	if e.Error != "" {
		return fmt.Errorf(e.Error)
	}
	if strings.TrimSpace(resp.AccessToken) == "" {
		return fmt.Errorf("empty token returned from oauth API, a wrong refresh token may have been used")
	}
	account.Token.AccessToken = resp.AccessToken
	if strings.TrimSpace(resp.RefreshToken) != "" {
		account.Token.RefreshToken = resp.RefreshToken
	}
	return d.updateAccountToken(index, account.Token)
}

func (d *GoogleDrive) refreshPrimaryAccount(ctx context.Context) error {
	if err := d.refreshAccount(ctx, 0); err != nil {
		return err
	}
	return d.syncPrimaryAccessToken()
}

func executeRequestWithToken(ctx context.Context, accessToken string, url string, method string, callback base.ReqCallback, resp interface{}) ([]byte, int, error) {
	req := base.RestyClient.R()
	if ctx != nil {
		req.SetContext(ctx)
	}
	req.SetHeader("Authorization", "Bearer "+accessToken)
	req.SetQueryParam("includeItemsFromAllDrives", "true")
	req.SetQueryParam("supportsAllDrives", "true")
	if callback != nil {
		callback(req)
	}
	if resp != nil {
		req.SetResult(resp)
	}
	res, err := req.Execute(method, url)
	if err != nil {
		return nil, 0, err
	}
	return res.Body(), res.StatusCode(), nil
}

func requestErrorFromBody(statusCode int, body []byte) error {
	var e Error
	if err := json.Unmarshal(body, &e); err == nil && (e.Error.Code != 0 || e.Error.Message != "") {
		return fmt.Errorf("%s: %v", e.Error.Message, e.Error.Errors)
	}
	return fmt.Errorf("google_drive: request failed with status %d", statusCode)
}

func isRetryableReadStatus(statusCode int, body []byte) bool {
	switch {
	case statusCode == http.StatusUnauthorized:
		return true
	case statusCode == http.StatusTooManyRequests:
		return true
	case statusCode >= http.StatusInternalServerError && statusCode < 600:
		return true
	case statusCode != http.StatusForbidden:
		return false
	}

	var driveErr Error
	if err := json.Unmarshal(body, &driveErr); err != nil {
		return false
	}
	retryableReasons := map[string]struct{}{
		"userRateLimitExceeded": {},
		"rateLimitExceeded":     {},
		"quotaExceeded":         {},
	}
	for _, item := range driveErr.Error.Errors {
		if _, ok := retryableReasons[item.Reason]; ok {
			return true
		}
	}
	return false
}

func isRetryableDownloadStatus(statusCode int, body []byte) bool {
	switch {
	case statusCode == http.StatusUnauthorized:
		return true
	case statusCode == http.StatusTooManyRequests:
		return true
	case statusCode == http.StatusForbidden:
		return true
	case statusCode >= http.StatusInternalServerError && statusCode < 600:
		return true
	case statusCode != http.StatusForbidden:
		return false
	}

	var driveErr Error
	if err := json.Unmarshal(body, &driveErr); err != nil {
		return false
	}
	retryableReasons := map[string]struct{}{
		"downloadQuotaExceeded": {},
		"userRateLimitExceeded": {},
		"rateLimitExceeded":     {},
		"quotaExceeded":         {},
	}
	for _, item := range driveErr.Error.Errors {
		if _, ok := retryableReasons[item.Reason]; ok {
			return true
		}
	}
	return false
}

func (d *GoogleDrive) requestDownloadWithRotation(ctx context.Context, url string, method string, callback base.ReqCallback, resp interface{}) (winningToken string, body []byte, err error) {
	d.accountStateMu.RLock()
	hasAccounts := len(d.accounts) > 0
	d.accountStateMu.RUnlock()
	if !hasAccounts {
		return "", nil, fmt.Errorf("google_drive: accounts_json must include at least one account")
	}
	attemptBudget := 1 + d.modeCfg.DownloadRetryMax
	order := d.accountPool.nextAttemptOrder(attemptBudget)
	if len(order) == 0 {
		return "", nil, fmt.Errorf("google_drive: accounts_json must include at least one account")
	}

	failures := make([]string, 0, len(order))
	for _, index := range order {
		account, err := d.accountSnapshot(index)
		if err != nil {
			return "", nil, err
		}
		body, statusCode, reqErr := executeRequestWithToken(ctx, account.Token.AccessToken, url, method, callback, resp)
		if reqErr != nil {
			return "", nil, reqErr
		}
		if statusCode == http.StatusUnauthorized {
			if refreshErr := d.refreshAccount(ctx, index); refreshErr == nil {
				account, err = d.accountSnapshot(index)
				if err != nil {
					return "", nil, err
				}
				body, statusCode, reqErr = executeRequestWithToken(ctx, account.Token.AccessToken, url, method, callback, resp)
				if reqErr != nil {
					return "", nil, reqErr
				}
			} else {
				if ctx != nil && ctx.Err() != nil {
					return "", nil, ctx.Err()
				}
				failures = append(failures, fmt.Sprintf("%s status %d refresh failed: %v", account.Name, statusCode, refreshErr))
				continue
			}
		}
		if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
			return account.Token.AccessToken, body, nil
		}

		failure := fmt.Sprintf("%s status %d", account.Name, statusCode)
		if !isRetryableDownloadStatus(statusCode, body) {
			return "", nil, fmt.Errorf("google_drive: non-retryable download error for %s", failure)
		}
		failures = append(failures, failure)
	}

	return "", nil, fmt.Errorf("google_drive: download rotation exhausted: %s", strings.Join(failures, "; "))
}

func (d *GoogleDrive) requestReadWithRotation(ctx context.Context, url string, method string, callback base.ReqCallback, resp interface{}) ([]byte, error) {
	d.accountStateMu.RLock()
	accountCount := len(d.accounts)
	d.accountStateMu.RUnlock()
	if accountCount == 0 {
		return nil, fmt.Errorf("google_drive: accounts_json must include at least one account")
	}
	attemptBudget := 1 + d.modeCfg.DownloadRetryMax
	order := d.accountPool.nextAttemptOrder(accountCount)
	if len(order) == 0 {
		return nil, fmt.Errorf("google_drive: accounts_json must include at least one account")
	}
	if attemptBudget > len(order) {
		attemptBudget = len(order)
	}
	primaryFirstOrder := make([]int, 0, len(order))
	primaryFirstOrder = append(primaryFirstOrder, 0)
	for _, index := range order {
		if index == 0 {
			continue
		}
		primaryFirstOrder = append(primaryFirstOrder, index)
	}
	order = primaryFirstOrder[:attemptBudget]

	var lastStatusCode int
	var lastBody []byte
	var lastErr error
	for _, index := range order {
		account, err := d.accountSnapshot(index)
		if err != nil {
			return nil, err
		}
		body, statusCode, reqErr := executeRequestWithToken(ctx, account.Token.AccessToken, url, method, callback, resp)
		if reqErr != nil {
			return nil, reqErr
		}
		if statusCode == http.StatusUnauthorized {
			if refreshErr := d.refreshAccount(ctx, index); refreshErr == nil {
				account, err = d.accountSnapshot(index)
				if err != nil {
					return nil, err
				}
				body, statusCode, reqErr = executeRequestWithToken(ctx, account.Token.AccessToken, url, method, callback, resp)
				if reqErr != nil {
					return nil, reqErr
				}
			} else {
				if ctx != nil && ctx.Err() != nil {
					return nil, ctx.Err()
				}
				lastErr = refreshErr
				lastStatusCode = statusCode
				lastBody = body
				continue
			}
		}
		if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
			if index == 0 {
				if err := d.syncPrimaryAccessToken(); err != nil {
					return nil, err
				}
			}
			return body, nil
		}
		if !isRetryableReadStatus(statusCode, body) {
			return nil, requestErrorFromBody(statusCode, body)
		}
		lastErr = nil
		lastStatusCode = statusCode
		lastBody = body
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, requestErrorFromBody(lastStatusCode, lastBody)
}
