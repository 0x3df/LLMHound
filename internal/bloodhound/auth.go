package bloodhound

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AuthConfig configures BloodHound CE API authentication.
// Precedence: BearerToken > (TokenID + TokenKey HMAC) > (Username + Password login).
type AuthConfig struct {
	TokenID     string
	TokenKey    string
	BearerToken string
	Username    string
	Password    string
}

// Validate checks that a complete authentication method was provided.
func (a AuthConfig) Validate() error {
	if strings.TrimSpace(a.BearerToken) != "" {
		return nil
	}
	if strings.TrimSpace(a.TokenID) != "" || strings.TrimSpace(a.TokenKey) != "" {
		if strings.TrimSpace(a.TokenID) == "" || strings.TrimSpace(a.TokenKey) == "" {
			return errors.New("bloodhound token authentication requires both token_id and token_key")
		}
		return nil
	}
	if strings.TrimSpace(a.Username) != "" || strings.TrimSpace(a.Password) != "" {
		if strings.TrimSpace(a.Username) == "" || strings.TrimSpace(a.Password) == "" {
			return errors.New("bloodhound password authentication requires both username and password")
		}
		return nil
	}
	return errors.New("bloodhound authentication required: provide token_id/token_key, bearer_token, or username/password")
}

// SignRequest applies BloodHound HMAC-SHA256 request signing (bhesignature).
func SignRequest(req *http.Request, tokenID, tokenKey string, body []byte, now time.Time) {
	requestDate := now.UTC().Format(time.RFC3339)

	// Stage 1: HMAC(tokenKey, METHOD + URI)
	digester := hmac.New(sha256.New, []byte(tokenKey))
	_, _ = digester.Write([]byte(req.Method + req.URL.RequestURI()))

	// Stage 2: HMAC(stage1, RFC3339[:13] e.g. "2026-11-21T12")
	digester2 := hmac.New(sha256.New, digester.Sum(nil))
	_, _ = digester2.Write([]byte(requestDate[:13]))

	// Stage 3: HMAC(stage2, body)
	digester3 := hmac.New(sha256.New, digester2.Sum(nil))
	if len(body) > 0 {
		_, _ = digester3.Write(body)
	}

	req.Header.Set("Authorization", "bhesignature "+tokenID)
	req.Header.Set("RequestDate", requestDate)
	req.Header.Set("Signature", base64.StdEncoding.EncodeToString(digester3.Sum(nil)))
}

func (c *Client) ensureBearerToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	tok := c.bearerToken
	c.mu.Unlock()
	if tok != "" {
		return tok, nil
	}
	if c.auth.Username == "" || c.auth.Password == "" {
		return "", errors.New("no bearer token or login credentials configured")
	}

	payload, err := json.Marshal(map[string]string{
		"login_method": "secret",
		"username":     c.auth.Username,
		"secret":       c.auth.Password,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v2/login", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("bloodhound login request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read login response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bloodhound login failed (HTTP %d)", resp.StatusCode)
	}

	var parsed struct {
		Data struct {
			SessionToken string `json:"session_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || strings.TrimSpace(parsed.Data.SessionToken) == "" {
		return "", errors.New("bloodhound login response missing session_token")
	}

	c.mu.Lock()
	c.bearerToken = parsed.Data.SessionToken
	c.mu.Unlock()
	return parsed.Data.SessionToken, nil
}
