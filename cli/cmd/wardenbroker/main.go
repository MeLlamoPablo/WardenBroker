// wardenbroker: the agent side of WardenBroker.
//
// An agent registers once (generating a P-256 key that never leaves this
// machine), then asks for secrets by host. The user approves on their phone,
// which encrypts the Bitwarden item to this agent's key; the broker only ever
// relays ciphertext.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

var version = "dev" // set by -ldflags in release builds

const (
	exitError    = 1
	exitUsage    = 2
	exitDenied   = 3
	exitTimeout  = 4
	pollWaitSecs = 25
)

type exitErr struct {
	code int
	err  error
}

func (e *exitErr) Error() string { return e.err.Error() }

func fail(code int, format string, args ...any) error {
	return &exitErr{code, fmt.Errorf(format, args...)}
}

var stderr io.Writer = os.Stderr

func main() {
	err := run(os.Args[1:])
	if err == nil {
		return
	}
	code := exitError
	var ee *exitErr
	if errors.As(err, &ee) {
		code = ee.code
	}
	var ce *childExit
	if errors.As(err, &ce) {
		os.Exit(ce.code)
	}
	fmt.Fprintln(stderr, "wardenbroker:", err)
	os.Exit(code)
}

const usage = `wardenbroker - let agents use your Bitwarden secrets, with your approval.

Usage:
  wardenbroker register --url <broker url> [--name <agent name>]
  wardenbroker get <host> --reason <why> [--field <field>] [--json]
  wardenbroker card --reason <why> [--field <field>] [--json]
  wardenbroker run --reason <why> -e VAR=<host>[:<field>] [-e ...] -- <command> [args...]
  wardenbroker status
  wardenbroker forget

Fields: password (default), username, totp (current code), totp-seed, notes,
        uri, or the name of any custom field.
Card fields: number (default), cardholder, brand, expiry (MM/YY), exp-month,
        exp-year, cvv.

Cards are not tied to a host: ` + "`card`" + ` asks for one and you pick which on your
phone. In ` + "`run`" + `, use @card as the host: -e CARD_NUMBER=@card:number

Exit codes: 0 ok, 1 error, 2 usage, 3 denied, 4 timed out / expired.
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return &exitErr{exitUsage, errors.New("missing command")}
	}
	switch args[0] {
	case "register":
		return cmdRegister(args[1:])
	case "get":
		return cmdGet(args[1:])
	case "card":
		return cmdCard(args[1:])
	case "run", "exec":
		return cmdRun(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "forget":
		return cmdForget(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return fail(exitUsage, "unknown command %q", args[0])
	}
}

// parseInterleaved lets flags appear before or after positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, &exitErr{exitUsage, err}
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		if args[0] == "--" {
			return append(positional, args[1:]...), nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// ---------------------------------------------------------------- register

func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	brokerURL := fs.String("url", os.Getenv("WARDENBROKER_URL"), "broker URL")
	host, _ := os.Hostname()
	name := fs.String("name", host, "a name for this agent, shown on your phone")
	timeout := fs.Duration("timeout", 15*time.Minute, "how long to wait for approval")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil && !errors.Is(err, errNotRegistered) {
		return err
	}
	if cfg != nil && cfg.Status == "active" {
		return fail(exitUsage, "already registered as %q with %s (run `wardenbroker forget` first to start over)", cfg.Name, cfg.URL)
	}
	if cfg != nil && cfg.Status == "pending" {
		fmt.Fprintf(stderr, "Resuming registration of %q with %s\n", cfg.Name, cfg.URL)
	} else {
		if *brokerURL == "" {
			return fail(exitUsage, "--url is required")
		}
		u, err := url.Parse(*brokerURL)
		if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
			return fail(exitUsage, "--url must be an https:// URL")
		}
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		pub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
		var res registerResponse
		if _, err := newClient(*brokerURL, "").do("POST", "/api/agent/register", map[string]string{"name": *name, "publicKey": pub}, &res); err != nil {
			return err
		}
		cfg = &Config{
			URL:        strings.TrimRight(*brokerURL, "/"),
			ID:         res.ID,
			Name:       *name,
			Token:      res.Token,
			PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
			Status:     "pending",
		}
		if err := cfg.save(); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "Registered %q with %s\n", cfg.Name, cfg.URL)
	}
	key, err := cfg.key()
	if err != nil {
		return err
	}
	fp := fingerprint(key.PublicKey().Bytes())
	fmt.Fprintf(stderr, "\n  Fingerprint: %s\n\nApprove this agent on your phone and check that the fingerprint matches.\nWaiting for approval…\n", fp)

	client := newClient(cfg.URL, cfg.Token)
	deadline := time.Now().Add(*timeout)
	for {
		var st statusResponse
		_, err := client.do("GET", fmt.Sprintf("/api/agent/status?wait=%d", pollWaitSecs), nil, &st)
		if err != nil {
			var api *APIError
			if errors.As(err, &api) && api.Status == 401 {
				_ = removeConfig()
				return fail(exitDenied, "the broker no longer knows this agent; register again")
			}
			if time.Now().After(deadline) {
				return fail(exitTimeout, "timed out waiting for approval (run `wardenbroker register` again to keep waiting)")
			}
			fmt.Fprintln(stderr, "  (connection problem, retrying:", err, ")")
			time.Sleep(3 * time.Second)
			continue
		}
		switch st.Status {
		case "active":
			cfg.Status = "active"
			if err := cfg.save(); err != nil {
				return err
			}
			fmt.Fprintln(stderr, "✓ Approved. This agent can now request secrets with `wardenbroker get`.")
			return nil
		case "denied":
			_ = removeConfig()
			return fail(exitDenied, "registration was denied")
		}
		if time.Now().After(deadline) {
			return fail(exitTimeout, "timed out waiting for approval (run `wardenbroker register` again to keep waiting)")
		}
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// fingerprint matches the broker's: first 8 bytes of SHA-256(public key), hex, in groups of 4.
func fingerprint(pub []byte) string {
	sum := sha256Sum(pub)
	hex := strings.ToUpper(fmt.Sprintf("%x", sum[:8]))
	return hex[0:4] + "-" + hex[4:8] + "-" + hex[8:12] + "-" + hex[12:16]
}

// --------------------------------------------------------------------- get

type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Card struct {
	CardholderName string `json:"cardholderName"`
	Brand          string `json:"brand"`
	Number         string `json:"number"`
	ExpMonth       string `json:"expMonth"`
	ExpYear        string `json:"expYear"`
	Code           string `json:"code"`
}

type Item struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Totp     string   `json:"totp"`
	Uris     []string `json:"uris"`
	Notes    string   `json:"notes"`
	Fields   []Field  `json:"fields"`
	Card     *Card    `json:"card,omitempty"`
}

type Payload struct {
	V          int    `json:"v"`
	Host       string `json:"host"`
	Item       Item   `json:"item"`
	ApprovedAt int64  `json:"approvedAt"`
}

func activeConfig() (*Config, *ecdh.PrivateKey, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	if cfg.Status != "active" {
		return nil, nil, fail(exitUsage, "registration is still pending: run `wardenbroker register` to finish it")
	}
	key, err := cfg.key()
	if err != nil {
		return nil, nil, err
	}
	return cfg, key, nil
}

// cardTarget stands in for a host when asking for a payment card. Cards aren't
// tied to a site, so the request names no host and the user picks the card on
// their phone. It matches the broker's CARD_TARGET, which is also what the
// secret is sealed to.
const cardTarget = "@card"

// resolveTarget turns a user-supplied host (or @card) into the request target.
func resolveTarget(input string) string {
	if strings.EqualFold(strings.TrimSpace(input), cardTarget) {
		return cardTarget
	}
	return normalizeHost(input)
}

// describeTarget is how a target reads in a message.
func describeTarget(target string) string {
	if target == cardTarget {
		return "a payment card"
	}
	return target
}

// normalizeHost mirrors the broker so we can bind the decryption to the same string.
func normalizeHost(input string) string {
	raw := strings.ToLower(strings.TrimSpace(input))
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(u.Hostname(), ".")
}

func requestSecret(cfg *Config, key *ecdh.PrivateKey, target, reason string, timeout time.Duration, announce func()) (*Payload, error) {
	host := resolveTarget(target)
	if host == "" {
		return nil, fail(exitUsage, "invalid host")
	}
	body := map[string]string{"host": host, "reason": reason}
	if host == cardTarget {
		body = map[string]string{"kind": "card", "reason": reason}
	}
	client := newClient(cfg.URL, cfg.Token)
	var res secretResponse
	if _, err := client.do("POST", "/api/agent/requests", body, &res); err != nil {
		var api *APIError
		if errors.As(err, &api) && api.Status == 403 {
			return nil, fail(exitDenied, "%s", api.Message)
		}
		return nil, err
	}
	if res.Status == "pending" {
		if announce != nil {
			announce()
		}
		deadline := time.Now().Add(timeout)
		id := res.ID
		for res.Status == "pending" {
			if time.Now().After(deadline) {
				return nil, fail(exitTimeout, "timed out waiting for approval of %s", describeTarget(host))
			}
			res = secretResponse{}
			if _, err := client.do("GET", fmt.Sprintf("/api/agent/requests/%s?wait=%d", id, pollWaitSecs), nil, &res); err != nil {
				var api *APIError
				if errors.As(err, &api) && api.Status < 500 {
					return nil, err
				}
				fmt.Fprintln(stderr, "  (connection problem, retrying:", err, ")")
				time.Sleep(3 * time.Second)
				res.Status = "pending"
			}
		}
	}
	switch res.Status {
	case "approved":
	case "denied":
		return nil, fail(exitDenied, "access to %s was denied", describeTarget(host))
	case "expired":
		return nil, fail(exitTimeout, "the request for %s expired before it was approved", describeTarget(host))
	default:
		return nil, fmt.Errorf("unexpected request status %q", res.Status)
	}
	plain, err := openSealed(key, host, res.Ciphertext)
	if err != nil {
		return nil, err
	}
	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("decrypted payload is not valid: %w", err)
	}
	if p.Host != host {
		return nil, fmt.Errorf("secret was approved for %q, not %q", p.Host, host)
	}
	return &p, nil
}

func pick(item Item, field string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(field))
	if v, ok, err := pickCard(item, f); ok {
		return v, err
	}
	switch f {
	case "", "password":
		if item.Password != "" || f == "password" {
			if item.Password == "" {
				return "", noField(item, "password")
			}
			return item.Password, nil
		}
		// A card's main secret is its number.
		if item.Card != nil && item.Card.Number != "" {
			return item.Card.Number, nil
		}
		// API keys often live in a single custom field or in the notes.
		if len(item.Fields) == 1 && item.Fields[0].Value != "" {
			fmt.Fprintf(stderr, "wardenbroker: %q has no password, using custom field %q\n", item.Name, item.Fields[0].Name)
			return item.Fields[0].Value, nil
		}
		return "", noField(item, "password")
	case "username", "user":
		if item.Username == "" {
			return "", noField(item, "username")
		}
		return item.Username, nil
	case "totp", "otp", "code":
		if item.Totp == "" {
			return "", noField(item, "totp")
		}
		return totpCode(item.Totp, time.Now())
	case "totp-seed":
		if item.Totp == "" {
			return "", noField(item, "totp")
		}
		return item.Totp, nil
	case "notes", "note":
		if item.Notes == "" {
			return "", noField(item, "notes")
		}
		return item.Notes, nil
	case "uri", "url":
		if len(item.Uris) == 0 {
			return "", noField(item, "uri")
		}
		return item.Uris[0], nil
	}
	name := strings.TrimPrefix(f, "field:")
	for _, fl := range item.Fields {
		if strings.ToLower(fl.Name) == name {
			return fl.Value, nil
		}
	}
	return "", noField(item, field)
}

// pickCard handles the card fields of a card item. ok is false when the item
// isn't a card or f isn't a card field, so a login's custom field called, say,
// "number" still works.
func pickCard(item Item, f string) (value string, ok bool, err error) {
	if item.Card == nil {
		return "", false, nil
	}
	c := *item.Card
	need := func(name, v string) (string, bool, error) {
		if v == "" {
			return "", true, noField(item, name)
		}
		return v, true, nil
	}
	switch f {
	case "number", "card-number":
		return need("number", c.Number)
	case "cardholder", "cardholder-name", "holder":
		return need("cardholder", c.CardholderName)
	case "brand":
		return need("brand", c.Brand)
	case "cvv", "cvc", "security-code":
		return need("cvv", c.Code)
	case "exp-month":
		return need("exp-month", expMonth(c.ExpMonth))
	case "exp-year":
		return need("exp-year", expYear(c.ExpYear))
	case "expiry", "exp", "expiration":
		m, y := expMonth(c.ExpMonth), expYear(c.ExpYear)
		if m == "" || len(y) < 2 {
			return need("expiry", "")
		}
		return m + "/" + y[len(y)-2:], true, nil
	}
	return "", false, nil
}

// expMonth zero-pads Bitwarden's "1".."12" to the "01".."12" card forms expect.
func expMonth(m string) string {
	m = strings.TrimSpace(m)
	if len(m) == 1 && m[0] >= '1' && m[0] <= '9' {
		return "0" + m
	}
	return m
}

// expYear expands a two-digit year to four digits.
func expYear(y string) string {
	y = strings.TrimSpace(y)
	if len(y) == 2 {
		return "20" + y
	}
	return y
}

func available(item Item) []string {
	var out []string
	if c := item.Card; c != nil {
		for _, f := range []struct {
			name string
			ok   bool
		}{
			{"number", c.Number != ""}, {"cardholder", c.CardholderName != ""}, {"brand", c.Brand != ""},
			{"expiry", c.ExpMonth != "" && c.ExpYear != ""}, {"cvv", c.Code != ""},
		} {
			if f.ok {
				out = append(out, f.name)
			}
		}
	}
	if item.Password != "" {
		out = append(out, "password")
	}
	if item.Username != "" {
		out = append(out, "username")
	}
	if item.Totp != "" {
		out = append(out, "totp")
	}
	if item.Notes != "" {
		out = append(out, "notes")
	}
	if len(item.Uris) > 0 {
		out = append(out, "uri")
	}
	for _, f := range item.Fields {
		out = append(out, fmt.Sprintf("%q", f.Name))
	}
	return out
}

func noField(item Item, field string) error {
	return fmt.Errorf("item %q has no %s (available: %s)", item.Name, field, strings.Join(available(item), ", "))
}

func cmdGet(args []string) error {
	return getCommand("get", "<host> ", "password", args)
}

// cmdCard asks for a payment card. It names no host: the user picks the card.
func cmdCard(args []string) error {
	return getCommand("card", "", "number", args)
}

// getCommand implements `get <host>` and `card`, which differ only in their target.
func getCommand(name, hostArg, defaultField string, args []string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	reason := fs.String("reason", "", "why you need this secret (shown to the user)")
	field := fs.String("field", "", "which field to print (default: "+defaultField+")")
	asJSON := fs.Bool("json", false, "print the whole item as JSON")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for approval")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	usage := fmt.Sprintf("usage: wardenbroker %s %s--reason <why>", name, hostArg)
	target := cardTarget
	if hostArg != "" {
		if len(pos) != 1 {
			return fail(exitUsage, "%s", usage)
		}
		target = resolveTarget(pos[0])
	} else if len(pos) != 0 {
		return fail(exitUsage, "%s (cards aren't tied to a host: you pick the card on your phone)", usage)
	}
	if strings.TrimSpace(*reason) == "" {
		return fail(exitUsage, "--reason is required: tell the user why you need this secret")
	}
	cfg, key, err := activeConfig()
	if err != nil {
		return err
	}
	p, err := requestSecret(cfg, key, target, *reason, *timeout, func() {
		if target == cardTarget {
			fmt.Fprintln(stderr, "Waiting for you to pick a card on your phone…")
		} else {
			fmt.Fprintf(stderr, "Waiting for approval of %s on your phone…\n", target)
		}
	})
	if err != nil {
		return err
	}
	if *asJSON {
		out, _ := json.MarshalIndent(p.Item, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	value, err := pick(p.Item, *field)
	if err != nil {
		return err
	}
	fmt.Println(value)
	return nil
}

// --------------------------------------------------------------------- run

type envSpec struct {
	name, host, field string
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type childExit struct{ code int }

func (c *childExit) Error() string { return fmt.Sprintf("command exited with status %d", c.code) }

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	reason := fs.String("reason", "", "why the command needs these secrets (shown to the user)")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for approval")
	var envs multiFlag
	fs.Var(&envs, "e", "VAR=host[:field] or VAR=@card[:field] (repeatable)")
	if err := fs.Parse(args); err != nil {
		return &exitErr{exitUsage, err}
	}
	command := fs.Args()
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 || len(envs) == 0 {
		return fail(exitUsage, "usage: wardenbroker run --reason <why> -e VAR=host[:field] -- <command> [args...]")
	}
	if strings.TrimSpace(*reason) == "" {
		return fail(exitUsage, "--reason is required: tell the user why the command needs these secrets")
	}
	var specs []envSpec
	for _, e := range envs {
		name, target, ok := strings.Cut(e, "=")
		if !ok || name == "" || target == "" {
			return fail(exitUsage, "invalid -e %q, expected VAR=host[:field]", e)
		}
		host, fieldName, _ := strings.Cut(target, ":")
		specs = append(specs, envSpec{name, host, fieldName})
	}
	cfg, key, err := activeConfig()
	if err != nil {
		return err
	}
	// Ask for every host at once so they all show up on the phone together.
	hosts := map[string]bool{}
	for _, s := range specs {
		target := resolveTarget(s.host)
		if target == "" {
			return fail(exitUsage, "invalid host %q", s.host)
		}
		hosts[target] = true
	}
	var names []string
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)
	payloads := map[string]*Payload{}
	var mu sync.Mutex
	var firstErr error
	var once sync.Once
	var wg sync.WaitGroup
	for _, h := range names {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			p, err := requestSecret(cfg, key, h, *reason, *timeout, func() {
				once.Do(func() {
					described := make([]string, len(names))
					for i, n := range names {
						described[i] = describeTarget(n)
					}
					fmt.Fprintf(stderr, "Waiting for approval of %s on your phone…\n", strings.Join(described, ", "))
				})
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			payloads[h] = p
		}(h)
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	env := os.Environ()
	for _, s := range specs {
		value, err := pick(payloads[resolveTarget(s.host)].Item, s.field)
		if err != nil {
			return err
		}
		env = append(env, s.name+"="+value)
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &childExit{ee.ExitCode()}
		}
		return err
	}
	return nil
}

// ------------------------------------------------------------ status/forget

func cmdStatus(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	key, err := cfg.key()
	if err != nil {
		return err
	}
	var st statusResponse
	_, err = newClient(cfg.URL, cfg.Token).do("GET", "/api/agent/status", nil, &st)
	remote := st.Status
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 401 || apiErr.Status == 403) {
		remote = "denied"
	} else if err != nil {
		remote = "unreachable (" + err.Error() + ")"
	}
	fmt.Printf("broker:      %s\nagent:       %s\nfingerprint: %s\nstatus:      %s\n", cfg.URL, cfg.Name, fingerprint(key.PublicKey().Bytes()), remote)
	if remote == "denied" {
		return fail(exitDenied, "this agent was denied or disconnected")
	}
	return nil
}

func removeConfig() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func cmdForget(args []string) error {
	if err := removeConfig(); err != nil {
		return err
	}
	fmt.Fprintln(stderr, "Forgot this agent's key and token. Disconnect it in the app too if it is still listed.")
	return nil
}
