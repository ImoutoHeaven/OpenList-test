package model

import "time"

// GoogleDriveAccountHealth stores the durable parts of a shared account's
// download health state. Short-lived evidence and backoff remain in memory.
type GoogleDriveAccountHealth struct {
	AccountKey      string    `json:"account_key" gorm:"primaryKey"`
	AccountName     string    `json:"account_name"`
	Generation      uint64    `json:"generation"`
	CooldownUntil   time.Time `json:"cooldown_until"`
	NextProbeAt     time.Time `json:"next_probe_at"`
	ProbeBudget     int       `json:"probe_budget"`
	ProbeUsed       int       `json:"probe_used"`
	ProbeFileIDs    string    `json:"probe_file_ids" gorm:"type:text"`
	ProbeRequired   bool      `json:"probe_required"`
	LiveTrialID     string    `json:"live_trial_id"`
	LiveTrialFileID string    `json:"live_trial_file_id"`
	LiveTrialUntil  time.Time `json:"live_trial_until"`
	UpdatedAt       time.Time `json:"updated_at"`
}
