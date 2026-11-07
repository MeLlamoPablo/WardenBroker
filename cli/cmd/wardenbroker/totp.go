package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// totpCode computes the current code for a Bitwarden TOTP value: either a bare
// base32 secret or an otpauth:// URI.
func totpCode(seed string, now time.Time) (string, error) {
	secret := strings.TrimSpace(seed)
	digits, period := 6, int64(30)
	alg := "SHA1"
	if strings.HasPrefix(strings.ToLower(secret), "otpauth://") {
		u, err := url.Parse(secret)
		if err != nil {
			return "", fmt.Errorf("invalid otpauth URI: %w", err)
		}
		q := u.Query()
		secret = q.Get("secret")
		if d, err := strconv.Atoi(q.Get("digits")); err == nil && d >= 6 && d <= 10 {
			digits = d
		}
		if p, err := strconv.ParseInt(q.Get("period"), 10, 64); err == nil && p > 0 {
			period = p
		}
		if a := q.Get("algorithm"); a != "" {
			alg = strings.ToUpper(a)
		}
	} else if strings.HasPrefix(strings.ToLower(secret), "steam://") {
		return "", fmt.Errorf("steam guard TOTP is not supported")
	}
	secret = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("TOTP secret is not valid base32: %w", err)
	}
	var h func() hash.Hash
	switch alg {
	case "SHA1":
		h = sha1.New
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		return "", fmt.Errorf("unsupported TOTP algorithm %s", alg)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/period))
	mac := hmac.New(h, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod), nil
}
