package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	URL   string
	Token string
	http  *http.Client
}

type APIError struct {
	Status  int
	Message string
	Body    map[string]any
}

func (e *APIError) Error() string { return fmt.Sprintf("broker: %s (HTTP %d)", e.Message, e.Status) }

func newClient(url, token string) *Client {
	return &Client{URL: strings.TrimRight(url, "/"), Token: token, http: &http.Client{Timeout: 45 * time.Second}}
}

func (c *Client) do(method, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.URL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", "wardenbroker-cli/"+version)
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("authorization", "Bearer "+c.Token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return res.StatusCode, err
	}
	var generic map[string]any
	_ = json.Unmarshal(data, &generic)
	if res.StatusCode >= 400 && (generic == nil || generic["status"] == nil) {
		msg, _ := generic["error"].(string)
		if msg == "" {
			msg = strings.TrimSpace(string(data))
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		return res.StatusCode, &APIError{Status: res.StatusCode, Message: msg, Body: generic}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return res.StatusCode, fmt.Errorf("unexpected response from broker: %w", err)
		}
	}
	return res.StatusCode, nil
}

type registerResponse struct {
	ID          string `json:"id"`
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
}

type statusResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
}

type secretResponse struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Host           string `json:"host"`
	Ciphertext     string `json:"ciphertext"`
	ItemName       string `json:"itemName"`
	GrantExpiresAt *int64 `json:"grantExpiresAt"`
}
