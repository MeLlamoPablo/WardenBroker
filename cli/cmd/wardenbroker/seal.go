package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// The phone seals each secret to this agent's P-256 key (ECIES):
//
//	0x01 || ephemeral public key (65) || nonce (12) || AES-256-GCM ciphertext+tag
//
// key = HKDF-SHA256(ECDH(eph, agent), salt = eph || agent, info = "wardenbroker/v1 seal")
// aad = "wardenbroker/v1|" + host, so a secret approved for one host can't be
// replayed by the broker as the answer for another.
const sealVersion = 1

func openSealed(priv *ecdh.PrivateKey, host, blob string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("ciphertext is not base64url: %w", err)
	}
	if len(raw) < 1+65+12+16 {
		return nil, errors.New("ciphertext too short")
	}
	if raw[0] != sealVersion {
		return nil, fmt.Errorf("unsupported ciphertext version %d", raw[0])
	}
	ephRaw, nonce, ct := raw[1:66], raw[66:78], raw[78:]
	eph, err := ecdh.P256().NewPublicKey(ephRaw)
	if err != nil {
		return nil, fmt.Errorf("bad ephemeral key: %w", err)
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	salt := append(append([]byte{}, ephRaw...), priv.PublicKey().Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, salt, "wardenbroker/v1 seal", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte("wardenbroker/v1|"+host))
	if err != nil {
		return nil, errors.New("could not decrypt the secret: it was not sealed for this agent and host")
	}
	return plain, nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
