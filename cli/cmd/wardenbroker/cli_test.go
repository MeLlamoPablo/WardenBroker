package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

// sealForTest mirrors web/src/seal.ts.
func sealForTest(t *testing.T, pub *ecdh.PublicKey, host string, plain []byte) string {
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(pub)
	salt := append(append([]byte{}, eph.PublicKey().Bytes()...), pub.Bytes()...)
	key, _ := hkdf.Key(sha256.New, shared, salt, "wardenbroker/v1 seal", 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append([]byte{1}, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, []byte("wardenbroker/v1|"+host))
	return base64.RawURLEncoding.EncodeToString(out)
}

func TestSealRoundTrip(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	blob := sealForTest(t, priv.PublicKey(), "github.com", []byte("hunter2"))
	got, err := openSealed(priv, "github.com", blob)
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := openSealed(priv, "gitlab.com", blob); err == nil {
		t.Fatal("opening with a different host must fail")
	}
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := openSealed(other, "github.com", blob); err == nil {
		t.Fatal("opening with a different key must fail")
	}
}

func TestTOTPVectors(t *testing.T) {
	// RFC 6238 appendix B, SHA1, 8 digits.
	seed := "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"
	cases := map[int64]string{59: "94287082", 1111111109: "07081804", 1234567890: "89005924", 2000000000: "69279037"}
	for ts, want := range cases {
		got, err := totpCode(seed, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %s %v, want %s", ts, got, err, want)
		}
	}
	if got, _ := totpCode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", time.Unix(59, 0)); got != "287082" {
		t.Errorf("bare secret: got %s", got)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"GitHub.com":                  "github.com",
		"https://api.github.com/user": "api.github.com",
		"db.example.com:5432":         "db.example.com",
		"example.com.":                "example.com",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestPick(t *testing.T) {
	item := Item{Name: "OpenAI", Fields: []Field{{Name: "API Key", Value: "sk-1"}}}
	if v, err := pick(item, ""); err != nil || v != "sk-1" {
		t.Fatalf("fallback to single custom field: %q %v", v, err)
	}
	if v, _ := pick(item, "api key"); v != "sk-1" {
		t.Fatal("custom field lookup is case-insensitive")
	}
	if _, err := pick(item, "username"); err == nil {
		t.Fatal("missing field must error")
	}
}

func TestPickCard(t *testing.T) {
	card := Item{Name: "Visa", Card: &Card{CardholderName: "Ada Lovelace", Brand: "Visa", Number: "4111111111111111", ExpMonth: "3", ExpYear: "2029", Code: "123"}}
	for field, want := range map[string]string{
		"":           "4111111111111111", // a card's main secret is its number
		"number":     "4111111111111111",
		"cardholder": "Ada Lovelace",
		"brand":      "Visa",
		"cvv":        "123",
		"CVC":        "123",
		"exp-month":  "03",
		"exp-year":   "2029",
		"expiry":     "03/29",
	} {
		if got, err := pick(card, field); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", field, got, err, want)
		}
	}
	short := Item{Name: "MC", Card: &Card{Number: "5555", ExpMonth: "11", ExpYear: "31"}}
	if got, _ := pick(short, "exp-year"); got != "2031" {
		t.Errorf("two-digit year: got %q", got)
	}
	if got, _ := pick(short, "expiry"); got != "11/31" {
		t.Errorf("expiry: got %q", got)
	}
	if _, err := pick(short, "cvv"); err == nil {
		t.Error("missing cvv must error")
	}
	if _, err := pick(Item{Name: "x", Card: &Card{ExpMonth: "1", ExpYear: "7"}}, "expiry"); err == nil {
		t.Error("a malformed year must error, not panic")
	}
	login := Item{Name: "Shop", Fields: []Field{{Name: "Number", Value: "42"}}}
	if got, err := pick(login, "number"); err != nil || got != "42" {
		t.Errorf("a login's custom field named like a card field: got %q, %v", got, err)
	}
}

func TestResolveTarget(t *testing.T) {
	for in, want := range map[string]string{"@card": cardTarget, " @CARD ": cardTarget, "card": "card", "https://shop.example/pay": "shop.example"} {
		if got := resolveTarget(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestCardSealIsBoundToTheCardTarget(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	blob := sealForTest(t, priv.PublicKey(), "shop.example", []byte("{}"))
	if _, err := openSealed(priv, cardTarget, blob); err == nil {
		t.Fatal("a secret sealed for a host must not open as a card")
	}
}

func TestFingerprintMatchesBrokerFormat(t *testing.T) {
	fp := fingerprint([]byte("x"))
	if len(fp) != 19 || fp[4] != '-' {
		t.Fatalf("bad fingerprint %q", fp)
	}
}
