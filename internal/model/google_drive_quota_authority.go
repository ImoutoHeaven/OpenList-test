package model

import "time"

// GoogleDriveQuotaAuthority stores the compact durable snapshot owned by the
// single OpenList authority. The payload schema is private to the Google
// driver; keeping it in one row makes restart recovery atomic.
type GoogleDriveQuotaAuthority struct {
	Key       string    `json:"key" gorm:"primaryKey"`
	Payload   string    `json:"payload" gorm:"type:text"`
	UpdatedAt time.Time `json:"updated_at"`
}
