package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultAPI = "https://fileion.com/api/v1"

// Exit codes (frozen, see docs/DESIGN.md section 3).
const (
	exitOK       = 0
	exitNotFound = 1
	exitUsage    = 2
	exitAPI      = 3
	exitRate     = 4
)

// Replaced in tests.
var (
	sleepFn    = time.Sleep
	reqTimeout = 15 * time.Second
)

// cliErr is any failure with a fixed exit code.
type cliErr struct {
	code           int
	apiCode, msg   string
	reqID, keysURL string
}

func (e *cliErr) Error() string {
	if e.reqID != "" {
		return e.msg + " (request " + e.reqID + ")"
	}
	return e.msg
}

type client struct {
	base, key string
	maxWait   int
	hc        *http.Client
}

func newClient(o *opts) (*client, error) {
	u, err := url.Parse(o.apiURL)
	if err != nil || u.Host == "" {
		return nil, &cliErr{code: exitUsage, msg: "bad --api-url"}
	}
	if h := u.Hostname(); u.Scheme != "https" && !(u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")) {
		return nil, &cliErr{code: exitUsage, msg: "--api-url must be https (http only for localhost)"}
	}
	return &client{base: strings.TrimRight(o.apiURL, "/"), key: o.key, maxWait: o.maxWait, hc: &http.Client{
		Timeout: reqTimeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Host != via[0].URL.Host || len(via) > 5 {
				return errors.New("redirect to another host refused")
			}
			return nil
		}}}, nil
}

// do sends one API call. Retries: connection errors and 502/503/504 twice with backoff; a 429 once, when Retry-After fits --max-wait.
func (c *client) do(method, path string, body []byte) ([]byte, error) {
	waited := false
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
		if err != nil {
			return nil, &cliErr{code: exitUsage, msg: "bad request address"}
		}
		req.Header.Set("User-Agent", "fileion-cli/"+version)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.key != "" {
			req.Header.Set("Authorization", "Bearer "+c.key)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			if attempt < 2 {
				sleepFn(time.Duration(1<<attempt) * time.Second)
				continue
			}
			return nil, &cliErr{code: exitAPI, apiCode: "network", msg: "cannot reach the Fileion API: " + err.Error()}
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		st := resp.StatusCode
		switch {
		case st >= 200 && st < 300 && rerr == nil:
			return data, nil
		case st == 429:
			ra := retryAfter(resp.Header.Get("Retry-After"))
			wait := ra
			if wait < 0 {
				wait = 5
			}
			if !waited && c.maxWait > 0 && wait <= c.maxWait {
				waited = true
				sleepFn(time.Duration(wait) * time.Second)
				continue
			}
			e := apiError(st, data)
			e.code, e.msg = exitRate, "rate limited, try again later"
			if ra >= 0 {
				e.msg = fmt.Sprintf("rate limited, retry after %d s", ra)
			}
			return nil, e
		case (st == 502 || st == 503 || st == 504) && attempt < 2:
			sleepFn(time.Duration(1<<attempt) * time.Second)
			continue
		}
		e := apiError(st, data)
		if st == 404 && e.apiCode == "not_found" {
			e.code = exitNotFound
		}
		return nil, e
	}
}

// retryAfter reads a number of seconds, or -1 when the header is missing or not a number.
func retryAfter(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// apiError reads the API's {"error": {...}} body; other bodies give a plain status message.
func apiError(status int, data []byte) *cliErr {
	var b struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
			KeysURL   string `json:"keys_url"`
		} `json:"error"`
	}
	e := &cliErr{code: exitAPI, msg: fmt.Sprintf("unexpected answer from the API (HTTP %d)", status)}
	if json.Unmarshal(data, &b) == nil && b.Error.Code != "" {
		e.apiCode, e.reqID, e.keysURL = b.Error.Code, b.Error.RequestID, b.Error.KeysURL
		e.msg = b.Error.Message
		if e.msg == "" {
			e.msg = b.Error.Code
		}
	}
	return e
}
