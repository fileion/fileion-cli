package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	hEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hA     = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
)

// fake is a stand-in API: it answers per path and records what it saw.
type fake struct {
	srv              *httptest.Server
	hits             int32
	lastAuth, lastUA string
	posts            []int
	handler          func(w http.ResponseWriter, r *http.Request)
}

func newFake(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *fake {
	f := &fake{handler: h}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.hits, 1)
		f.lastAuth, f.lastUA = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	sleepFn = func(time.Duration) {}
	t.Cleanup(func() { sleepFn = time.Sleep; reqTimeout = 15 * time.Second })
	return f
}

func reply(w http.ResponseWriter, status int, body string, hdr ...string) {
	for i := 0; i+1 < len(hdr); i += 2 {
		w.Header().Set(hdr[i], hdr[i+1])
	}
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func do(t *testing.T, f *fake, stdin string, envKey string, args ...string) (int, string, string) {
	var so, se bytes.Buffer
	e := env{strings.NewReader(stdin), &so, &se, func(k string) string {
		if k == "FILEION_API_KEY" {
			return envKey
		}
		return ""
	}, false}
	if f != nil {
		args = append(args, "--api-url", f.srv.URL)
	}
	code := run(args, e)
	return code, so.String(), se.String()
}

func tmpFile(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "a.bin")
	os.WriteFile(p, []byte(content), 0o600)
	return p
}

func foundItem(hash string) string {
	return `{"found":true,"hash":"` + hash + `","software":{"slug":"vlc","name":"VLC media player","url":"https://vlc.fileion.com"},"version":{"id":1,"version":"3.0.21","released_at":"2026-10-30","platform":"windows"},"file":{"source":{"kind":"official","host":"get.videolan.org"},"scan":{"engines":70,"flagged":0,"scanned_at":"2026-11-02","report_url":"https://vt.example/r"}},"trust":{"state":"verified","label":"Fileion Verified","ok":4,"steps":{"source":{"status":"ok","text":"Official source"},"fingerprint":{"status":"ok","text":"Fingerprint"},"virustotal":{"status":"ok","text":"VirusTotal"},"signature":{"status":"ok","text":"Code signature"},"installer":{"status":"na","text":"Clean installer"}}}}`
}

func TestHashVectors(t *testing.T) {
	if h, _ := hashReader(strings.NewReader("")); h != hEmpty {
		t.Fatal("empty", h)
	}
	if h, _ := hashReader(strings.NewReader("a")); h != hA {
		t.Fatal("a", h)
	}
	// 100 MiB through a pipe: streamed, never held in memory
	const total = 100 << 20
	pr, pw := io.Pipe()
	want := sha256.New()
	go func() {
		chunk := make([]byte, 1<<20)
		for i := range chunk {
			chunk[i] = byte(i)
		}
		for i := 0; i < total>>20; i++ {
			want.Write(chunk)
			pw.Write(chunk)
		}
		pw.Close()
	}()
	got, err := hashReader(pr)
	if err != nil || got != hex.EncodeToString(want.Sum(nil)) {
		t.Fatal("100MiB", got, err)
	}
}

func TestCheckFoundAndUnknown(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/"+hA {
			reply(w, 200, `{"data":`+foundItem(hA)+`}`)
		} else {
			reply(w, 200, `{"data":{"found":false,"hash":"`+hEmpty+`"}}`)
		}
	})
	code, so, _ := do(t, f, "", "", "check", tmpFile(t, "a"), "--api-url", f.srv.URL)
	if code != 0 || !strings.Contains(so, "listed      yes, this build") || !strings.Contains(so, "VLC media player (vlc)") || !strings.Contains(so, "0 of 70 engines flagged this build, scanned 2026-11-02 (report: https://vt.example/r)") || !strings.Contains(so, "4 of 5 checks   https://vlc.fileion.com") || !strings.Contains(so, "Installer test not checked") {
		t.Fatalf("found: %d\n%s", code, so)
	}
	code, so, _ = do(t, f, "", "", "check", tmpFile(t, ""))
	if code != 1 || !strings.Contains(so, "listed      no. Fileion has no record of this build (this is not a warning)") {
		t.Fatalf("unknown: %d\n%s", code, so)
	}
	code, _, _ = do(t, f, "", "", "check", tmpFile(t, ""), "--allow-unknown")
	if code != 0 {
		t.Fatal("allow-unknown", code)
	}
	if f.lastUA != "fileion-cli/dev" {
		t.Fatal("UA", f.lastUA)
	}
}

func TestNoVerdictWords(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) { reply(w, 200, `{"data":`+foundItem(hA)+`}`) })
	_, plain, _ := do(t, f, "a", "", "check", "-")
	_, js, _ := do(t, f, "a", "", "check", "-", "--json")
	for _, s := range []string{plain, js} {
		l := strings.ToLower(s)
		for _, w := range []string{"safe", "clean", "virus-free", "verified"} {
			if strings.Contains(l, w) {
				t.Fatalf("%q in output:\n%s", w, s)
			}
		}
	}
}

func TestCheckJSONMixedBatchAndStdin(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/files/lookup" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var b struct{ Hashes []string }
		json.NewDecoder(r.Body).Decode(&b)
		var items []string
		for _, h := range b.Hashes {
			if h == hA {
				items = append(items, foundItem(h))
			} else {
				items = append(items, `{"found":false,"hash":"`+h+`"}`)
			}
		}
		reply(w, 200, `{"data":[`+strings.Join(items, ",")+`]}`)
	})
	p := tmpFile(t, "a")
	code, so, se := do(t, f, "", "", "check", p, filepath.Join(t.TempDir(), "missing"), "--hash", hEmpty, "--json")
	if code != 2 {
		t.Fatalf("a missing file is a usage error: %d\n%s", code, se)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(so), &arr); err != nil || len(arr) != 3 {
		t.Fatalf("json: %v\n%s", err, so)
	}
	if arr[0]["found"] != true || arr[0]["path"] != p || arr[1]["error"] == nil || arr[2]["found"] != false {
		t.Fatalf("order or fields: %s", so)
	}
	if tr := arr[0]["trust"].(map[string]any); tr["label"] != nil || tr["state"] != nil || tr["ok"] != float64(4) {
		t.Fatal("trust not trimmed", tr)
	}
	if !strings.Contains(so, "Installer test") || strings.Contains(so, "Clean installer") {
		t.Fatal("step 5 name")
	}
}

func TestCheckChunksOf100(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Hashes []string }
		json.NewDecoder(r.Body).Decode(&b)
		var items []string
		for _, h := range b.Hashes {
			items = append(items, `{"found":false,"hash":"`+h+`"}`)
		}
		reply(w, 200, `{"data":[`+strings.Join(items, ",")+`]}`)
	})
	args := []string{"check", "--allow-unknown", "-q"}
	for i := 0; i < 101; i++ {
		args = append(args, "--hash", fmt.Sprintf("%064x", i+1))
	}
	if code, _, se := do(t, f, "", "", args...); code != 0 || f.hits != 2 {
		t.Fatalf("code %d hits %d %s", code, f.hits, se)
	}
}

func TestInfoAndLatest(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/software/vlc" {
			reply(w, 404, `{"error":{"code":"not_found","message":"Nothing found at this address.","request_id":"r1"}}`)
			return
		}
		reply(w, 200, `{"data":{"slug":"vlc","name":"VLC media player","url":"https://vlc.fileion.com","publisher":{"name":"VideoLAN"},"platforms":["windows","mac"],"license":"GPL-2.0","website":"https://www.videolan.org","latest":{"windows":{"id":1,"version":"3.0.21","released_at":"2026-10-30"},"mac":{"id":2,"version":"3.0.20","released_at":"2026-09-01"},"linux":null}}}`)
	})
	_, so, _ := do(t, f, "", "", "info", "vlc")
	want := "VLC media player (vlc)\n  publisher   VideoLAN\n  platforms   windows, mac\n  licence     GPL-2.0\n  website     https://www.videolan.org\n  page        https://vlc.fileion.com\n"
	if so != want {
		t.Fatalf("info:\n%s", so)
	}
	_, so, _ = do(t, f, "", "", "latest", "vlc", "-p", "Windows")
	if so != "3.0.21\n" {
		t.Fatalf("latest -p: %q", so)
	}
	_, so, _ = do(t, f, "", "", "latest", "vlc")
	if so != "mac       3.0.20  2026-09-01\nwindows   3.0.21  2026-10-30\n" {
		t.Fatalf("latest: %q", so)
	}
	if code, so, _ := do(t, f, "", "", "latest", "vlc", "-p", "linux", "--json"); code != 1 || !strings.Contains(so, `"not_found"`) {
		t.Fatalf("no linux: %d %s", code, so)
	}
	if code, so, se := do(t, f, "", "", "info", "nope", "--json"); code != 1 || !strings.Contains(se, "no title with the address nope (request r1)") || !strings.Contains(so, `"request_id":"r1"`) {
		t.Fatalf("404: %d %s %s", code, so, se)
	}
}

func TestErrorsAndExitCodes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		hdr    []string
		want   int
	}{
		{"401", 401, `{"error":{"code":"invalid_key","message":"bad key","request_id":"r"}}`, nil, 3},
		{"422", 422, `{"error":{"code":"invalid_parameter","message":"x"}}`, nil, 3},
		{"500", 500, `oops`, nil, 3},
		{"bad json", 200, `not json`, nil, 3},
		{"429 too long", 429, `{"error":{"code":"rate_limited","keys_url":"https://fileion.com/keys"}}`, []string{"Retry-After", "120"}, 4},
		{"429 no header, wait 0", 429, `{}`, nil, 4},
	}
	for _, c := range cases {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request) { reply(w, c.status, c.body, c.hdr...) })
		args := []string{"info", "vlc"}
		if c.name == "429 no header, wait 0" {
			args = append(args, "--max-wait", "0")
		}
		if code, _, se := do(t, f, "", "", args...); code != c.want {
			t.Errorf("%s: exit %d (%s)", c.name, code, se)
		}
	}
	for _, args := range [][]string{{}, {"nope"}, {"check"}, {"info"}, {"info", "a b"}, {"check", "--hash", "xyz"}, {"latest", "vlc", "--bogus"}} {
		if code, _, _ := do(t, nil, "", "", args...); code != 2 {
			t.Errorf("%v: want 2, got %d", args, code)
		}
	}
	if code, _, _ := do(t, nil, "", "", "info", "vlc", "--api-url", "http://example.com"); code != 2 {
		t.Error("plain http to a remote host must be refused")
	}
	// nothing listening: network error, exit 3
	if code, _, _ := do(t, nil, "", "", "info", "vlc", "--api-url", "http://127.0.0.1:1"); code != 3 {
		t.Error("network", code)
	}
}

func TestRateLimitWaitsOnceThenWorks(t *testing.T) {
	var n int32
	var slept time.Duration
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			reply(w, 429, `{"error":{"code":"rate_limited"}}`, "Retry-After", "7")
			return
		}
		reply(w, 200, `{"data":{"slug":"vlc","name":"VLC","latest":{"windows":{"version":"1"}}}}`)
	})
	sleepFn = func(d time.Duration) { slept += d }
	if code, so, _ := do(t, f, "", "", "latest", "vlc", "-p", "windows"); code != 0 || so != "1\n" || slept != 7*time.Second {
		t.Fatalf("code %d out %q slept %v", code, so, slept)
	}
	// a second 429 after the one retry is exit 4, with the message and the keys address on stderr
	f2 := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		reply(w, 429, `{"error":{"code":"rate_limited","keys_url":"https://fileion.com/developers/keys","request_id":"q9"}}`, "Retry-After", "3")
	})
	code, _, se := do(t, f2, "", "", "info", "vlc")
	if code != 4 || f2.hits != 2 || !strings.Contains(se, "rate limited, retry after 3 s (request q9)") || !strings.Contains(se, "https://fileion.com/developers/keys") {
		t.Fatalf("code %d hits %d\n%s", code, f2.hits, se)
	}
}

func TestServerErrorsRetriedThenFail(t *testing.T) {
	var n int32
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			reply(w, 503, `x`)
			return
		}
		reply(w, 200, `{"data":{"slug":"vlc","name":"VLC"}}`)
	})
	if code, _, _ := do(t, f, "", "", "info", "vlc"); code != 0 || n != 3 {
		t.Fatal("two 503s then ok:", code, n)
	}
	f = newFake(t, func(w http.ResponseWriter, r *http.Request) { reply(w, 503, `x`) })
	if code, _, _ := do(t, f, "", "", "info", "vlc"); code != 3 || f.hits != 3 {
		t.Fatal("always 503:", code, f.hits)
	}
}

func TestTimeout(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) })
	reqTimeout = 50 * time.Millisecond
	if code, _, se := do(t, f, "", "", "info", "vlc"); code != 3 || !strings.Contains(se, "cannot reach") {
		t.Fatal(code, se)
	}
}

func TestKeyPrecedenceAndNeverPrinted(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		reply(w, 401, `{"error":{"code":"invalid_key","message":"This API key is not valid or was revoked."}}`)
	})
	_, so, se := do(t, f, "", "fk_envkey", "info", "vlc")
	if f.lastAuth != "Bearer fk_envkey" {
		t.Fatal("env key", f.lastAuth)
	}
	_, so2, se2 := do(t, f, "", "fk_envkey", "info", "vlc", "--key", "fk_flagkey", "--json")
	if f.lastAuth != "Bearer fk_flagkey" {
		t.Fatal("flag wins", f.lastAuth)
	}
	for _, s := range []string{so, se, so2, se2} {
		if strings.Contains(s, "fk_") {
			t.Fatal("key printed:", s)
		}
	}
	if code, _, _ := do(t, f, "", "", "info", "vlc"); f.lastAuth != "" || code != 3 {
		t.Fatal("keyless sends no Authorization")
	}
}

func TestHelpVersionQuiet(t *testing.T) {
	if code, so, _ := do(t, nil, "", "", "help"); code != 0 || !strings.Contains(so, "Exit codes: 0 found") {
		t.Fatal("help")
	}
	if code, so, _ := do(t, nil, "", "", "version"); code != 0 || so != "fileion-cli dev\n" {
		t.Fatal("version", so)
	}
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) { reply(w, 200, `{"data":{"slug":"v","name":"V"}}`) })
	if code, so, se := do(t, f, "", "", "info", "v", "-q"); code != 0 || so != "" || se != "" {
		t.Fatal("quiet")
	}
}

func TestUsageErrorsAnswerInJSONWithJSONFlag(t *testing.T) {
	for _, args := range [][]string{{"check", "--json"}, {"info", "--json"}, {"nope", "--json"}, {"latest", "vlc", "--bogus", "--json"}} {
		code, so, se := do(t, nil, "", "", args...)
		var d struct {
			Error struct{ Code, Message string }
		}
		if code != 2 || json.Unmarshal([]byte(so), &d) != nil || d.Error.Code != "usage" || d.Error.Message == "" || se == "" {
			t.Errorf("%v: %d %q %q", args, code, so, se)
		}
	}
	if _, so, _ := do(t, nil, "", "", "check"); so != "" {
		t.Error("no JSON without --json")
	}
}

func TestStepsAsListStillCounted(t *testing.T) {
	list := `{"found":true,"hash":"` + hA + `","trust":{"ok":2,"steps":[{"status":"ok"},{"status":"ok"},{"status":"warn"},{"status":"na"},{"status":"na"}]}}`
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) { reply(w, 200, `{"data":`+list+`}`) })
	if _, so, _ := do(t, f, "a", "", "check", "-"); !strings.Contains(so, "2 of 5 checks") {
		t.Fatal(so)
	}
}
