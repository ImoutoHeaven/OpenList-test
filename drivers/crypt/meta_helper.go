package crypt

import (
	"context"
	"fmt"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/rclone/rclone/fs/config/obscure"
	"golang.org/x/crypto/scrypt"
)

var defaultScryptSalt = []byte{0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1}

const (
	dataKeyLen   = 32
	nameKeyLen   = 32
	nameTweakLen = 16
	scryptN      = 16384
	scryptR      = 8
	scryptP      = 1
)

func (d *Crypt) revealSecret(secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	raw := secret
	if strings.HasPrefix(raw, obfuscatedPrefix) {
		raw = strings.TrimPrefix(raw, obfuscatedPrefix)
		decoded, err := obscure.Reveal(raw)
		if err != nil {
			return "", err
		}
		return decoded, nil
	}
	return raw, nil
}

func (d *Crypt) DataKey() ([]byte, error) {
	password, err := d.revealSecret(d.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to reveal password: %w", err)
	}
	salt, err := d.revealSecret(d.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to reveal salt: %w", err)
	}
	const keySize = dataKeyLen + nameKeyLen + nameTweakLen
	key := make([]byte, keySize)
	if password != "" {
		saltBytes := defaultScryptSalt
		if salt != "" {
			saltBytes = []byte(salt)
		}
		derived, err := scrypt.Key([]byte(password), saltBytes, scryptN, scryptR, scryptP, keySize)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key: %w", err)
		}
		copy(key, derived)
	}
	dataKey := make([]byte, dataKeyLen)
	copy(dataKey, key[:dataKeyLen])
	return dataKey, nil
}

func (d *Crypt) RemoteLink(ctx context.Context, path string, args model.LinkArgs) (*model.Link, model.Obj, error) {
	actualPath, err := d.getActualPathForRemote(path, false)
	if err != nil {
		return nil, nil, err
	}
	return op.Link(ctx, d.remoteStorage, actualPath, args)
}

func (d *Crypt) EncryptedPath(path string, isFolder bool) string {
	return d.getPathForRemote(path, isFolder)
}

func (d *Crypt) EncryptedActualPath(path string, isFolder bool) (string, error) {
	return d.getActualPathForRemote(path, isFolder)
}
