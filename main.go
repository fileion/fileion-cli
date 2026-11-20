// fileion: check a file's SHA-256 against what Fileion lists, and look up a title. Reads only the public Fileion API.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

var version = "dev"

const usageText = `fileion: check files and look up software against the Fileion catalogue

Usage:
  fileion check <file>... | -      hash the file here (it is never uploaded) and ask Fileion if it lists that hash
  fileion check --hash <hex>       the same for a SHA-256, SHA-1 or MD5 you already have (repeat for several)
  fileion info <slug>              a title: publisher, platforms, licence, website
  fileion latest <slug> [-p os]    the newest version per platform (bare version with -p)
  fileion version | help

Options:
  --json            JSON on stdout (errors too)
  -q, --quiet       print nothing, exit code only
  --key <key>       API key (or env FILEION_API_KEY; the flag shows in process lists)
  --max-wait <s>    longest wait on a 429 Retry-After (default 30, 0 = never wait)
  --allow-unknown   check: exit 0 even when some hashes are unknown to Fileion
  -p, --platform    latest: windows, mac or linux

Exit codes: 0 found, 1 not found, 2 usage error, 3 network or API error, 4 rate limited.
`

type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	getenv         func(string) string
	json           bool // --json appears in the arguments (set by run, so usage errors can answer in JSON)
}

type opts struct {
	json, quiet, allowUnknown bool
	key, apiURL, platform     string
	maxWait                   int
	hashes                    strList
}

type strList []string

func (s *strList) String() string     { return strings.Join(*s, ",") }
func (s *strList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], env{os.Stdin, os.Stdout, os.Stderr, os.Getenv, false}))
}

func run(args []string, e env) int {
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usageText)
		return exitUsage
	}
	for _, a := range args {
		if a == "--json" || a == "-json" {
			e.json = true
		}
	}
	cmd := args[0]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(e.stdout, usageText)
		return exitOK
	case "version", "-version", "--version":
		fmt.Fprintf(e.stdout, "fileion-cli %s\n", version)
		return exitOK
	case "check", "info", "latest":
	default:
		return usageErr(e, "unknown command "+cmd)
	}
	o, pos, err := parse(cmd, args[1:], e)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(e.stdout, usageText)
		return exitOK
	}
	if err != nil {
		return usageErr(e, err.Error())
	}
	c, err := newClient(o)
	if err != nil {
		return usageErr(e, err.Error())
	}
	switch cmd {
	case "check":
		return cmdCheck(c, o, pos, e)
	case "info":
		return cmdInfo(c, o, pos, e)
	}
	return cmdLatest(c, o, pos, e)
}

// parse reads flags anywhere among the arguments.
func parse(cmd string, args []string, e env) (*opts, []string, error) {
	o := &opts{}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.quiet, "quiet", false, "")
	fs.BoolVar(&o.quiet, "q", false, "")
	fs.StringVar(&o.key, "key", "", "")
	fs.IntVar(&o.maxWait, "max-wait", 30, "")
	fs.StringVar(&o.apiURL, "api-url", defaultAPI, "") // for tests
	if cmd == "check" {
		fs.Var(&o.hashes, "hash", "")
		fs.BoolVar(&o.allowUnknown, "allow-unknown", false, "")
	}
	if cmd == "latest" {
		fs.StringVar(&o.platform, "platform", "", "")
		fs.StringVar(&o.platform, "p", "", "")
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if o.key == "" {
		o.key = e.getenv("FILEION_API_KEY")
	}
	return o, pos, nil
}

func usageErr(e env, msg string) int {
	fmt.Fprintf(e.stderr, "fileion: %s\nTry: fileion help\n", msg)
	if e.json {
		printJSON(e, &opts{}, map[string]any{"error": map[string]any{"code": "usage", "message": msg, "request_id": ""}})
	}
	return exitUsage
}

// fail prints a runtime error (stderr, plus JSON on stdout with --json) and returns its exit code.
func fail(e env, o *opts, err error) int {
	var ce *cliErr
	if !errors.As(err, &ce) {
		ce = &cliErr{code: exitAPI, msg: err.Error()}
	}
	if o.quiet {
		return ce.code
	}
	fmt.Fprintf(e.stderr, "fileion: %s\n", ce)
	if ce.keysURL != "" {
		fmt.Fprintf(e.stderr, "fileion: a free API key gives higher limits: %s\n", ce.keysURL)
	}
	if o.json {
		code := ce.apiCode
		if code == "" {
			code = "error"
		}
		printJSON(e, o, map[string]any{"error": map[string]any{"code": code, "message": ce.msg, "request_id": ce.reqID}})
	}
	return ce.code
}

func printJSON(e env, o *opts, v any) {
	if o.quiet {
		return
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	e.stdout.Write(b.Bytes())
}

func out(e env, o *opts, format string, a ...any) {
	if !o.quiet {
		fmt.Fprintf(e.stdout, format, a...)
	}
}

var (
	hexRe  = regexp.MustCompile(`^(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})$`)
	slugRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", errors.New(strings.TrimPrefix(err.Error(), path+": "))
	}
	if st.IsDir() {
		return "", errors.New("is a directory (check takes files only)")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New(strings.TrimPrefix(err.Error(), "open "+path+": "))
	}
	defer f.Close()
	return hashReader(f)
}

type item struct {
	path, hash string
	err        error
}

func cmdCheck(c *client, o *opts, pos []string, e env) int {
	if len(pos) == 0 && len(o.hashes) == 0 {
		return usageErr(e, "check needs a file, - for stdin, or --hash")
	}
	var items []item
	for _, p := range pos {
		var h string
		var err error
		if p == "-" {
			h, err = hashReader(e.stdin)
		} else {
			h, err = hashFile(p)
		}
		items = append(items, item{path: p, hash: h, err: err})
	}
	for _, h := range o.hashes {
		if !hexRe.MatchString(h) {
			return usageErr(e, "not a SHA-256, SHA-1 or MD5 hex string: "+h)
		}
		items = append(items, item{hash: strings.ToLower(h)})
	}
	var uniq []string
	seen := map[string]bool{}
	fileErr := false
	for _, it := range items {
		if it.err != nil {
			fileErr = true
		} else if !seen[it.hash] {
			seen[it.hash] = true
			uniq = append(uniq, it.hash)
		}
	}
	answers, apiErr := lookup(c, uniq)
	code := exitOK
	if fileErr {
		code = exitUsage
	}
	if apiErr != nil {
		for _, it := range items {
			if it.err != nil && !o.quiet {
				fmt.Fprintf(e.stderr, "fileion: %s: %s\n", it.path, it.err)
			}
		}
		if c := fail(e, o, apiErr); c > code {
			code = c
		}
		return code
	}
	var jsonOut []any
	unknown := 0
	for i, it := range items {
		label := it.path
		if label == "" {
			label = it.hash
		}
		if it.err != nil {
			if !o.quiet {
				fmt.Fprintf(e.stderr, "fileion: %s: %s\n", it.path, it.err)
			}
			jsonOut = append(jsonOut, map[string]any{"path": it.path, "error": it.err.Error()})
			continue
		}
		raw := answers[it.hash]
		var r fileRes
		json.Unmarshal(raw, &r)
		if !r.Found {
			unknown++
		}
		m := cleanItem(raw, it.path)
		jsonOut = append(jsonOut, m)
		if !o.json {
			if i > 0 {
				out(e, o, "\n")
			}
			renderFile(e, o, label, it.hash, r)
		}
	}
	if o.json {
		printJSON(e, o, jsonOut)
	}
	if unknown > 0 && !o.allowUnknown && code == exitOK {
		code = exitNotFound
	}
	return code
}

// lookup asks the API about the hashes: one GET for a single hash, else POST batches of 100.
func lookup(c *client, hashes []string) (map[string]json.RawMessage, error) {
	res := map[string]json.RawMessage{}
	if len(hashes) == 0 {
		return res, nil
	}
	if len(hashes) == 1 {
		b, err := c.do("GET", "/files/"+hashes[0], nil)
		if err != nil {
			return nil, err
		}
		var d struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(b, &d) != nil || len(d.Data) == 0 {
			return nil, &cliErr{code: exitAPI, msg: "unexpected answer from the API (not JSON data)"}
		}
		res[hashes[0]] = d.Data
		return res, nil
	}
	for i := 0; i < len(hashes); i += 100 {
		end := min(i+100, len(hashes))
		body, _ := json.Marshal(map[string][]string{"hashes": hashes[i:end]})
		b, err := c.do("POST", "/files/lookup", body)
		if err != nil {
			return nil, err
		}
		var d struct {
			Data []json.RawMessage `json:"data"`
		}
		if json.Unmarshal(b, &d) != nil {
			return nil, &cliErr{code: exitAPI, msg: "unexpected answer from the API (not JSON data)"}
		}
		for _, raw := range d.Data {
			var h struct {
				Hash string `json:"hash"`
			}
			json.Unmarshal(raw, &h)
			res[h.Hash] = raw
		}
	}
	for _, h := range hashes {
		if res[h] == nil {
			return nil, &cliErr{code: exitAPI, msg: "the API gave no answer for hash " + h}
		}
	}
	return res, nil
}

type fileRes struct {
	Found    bool                                `json:"found"`
	Software *struct{ Slug, Name, URL string }   `json:"software"`
	Version  *struct{ Version, Platform string } `json:"version"`
	File     *struct {
		FileName *string
		Size     *string
		Source   *struct{ Kind, Host string }
		Scan     *struct {
			Engines, Flagged int
			ScannedAt        *string `json:"scanned_at"`
			ReportURL        *string `json:"report_url"`
		}
	} `json:"file"`
	Trust *struct {
		OK    int
		Steps json.RawMessage
	} `json:"trust"`
}

var (
	stepNames = []string{"Official source", "Fingerprint", "VirusTotal", "Code signature", "Installer test"}
	stepKeys  = []string{"source", "fingerprint", "virustotal", "signature", "installer"}
)

// stepStatuses lists the trust steps' statuses in order. The API sends steps as an object keyed by check name
// (source, fingerprint, virustotal, signature, installer); a plain list is read too.
func stepStatuses(raw json.RawMessage) []string {
	type st struct{ Status string }
	var byKey map[string]st
	if json.Unmarshal(raw, &byKey) == nil && len(byKey) > 0 {
		var out []string
		for _, k := range stepKeys {
			if s, ok := byKey[k]; ok {
				out = append(out, s.Status)
			}
		}
		if len(out) == len(byKey) {
			return out
		}
		return nil
	}
	var list []st
	json.Unmarshal(raw, &list)
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.Status
	}
	return out
}

func renderFile(e env, o *opts, label, hash string, r fileRes) {
	out(e, o, "%s\n", label)
	row := func(k, v string) { out(e, o, "  %-12s%s\n", k, v) }
	if !r.Found {
		row("listed", "no. Fileion has no record of this file (this is not a warning)")
		row("sha256", hash)
		return
	}
	row("listed", "yes")
	if s := r.Software; s != nil {
		row("software", fmt.Sprintf("%s (%s)", s.Name, s.Slug))
	}
	if v := r.Version; v != nil {
		row("version", v.Version+", "+v.Platform)
	}
	if f := r.File; f != nil {
		if f.Source != nil {
			row("source", fmt.Sprintf("%s (%s)", f.Source.Kind, f.Source.Host))
		}
		if sc := f.Scan; sc != nil {
			s := fmt.Sprintf("%d of %d engines flagged", sc.Flagged, sc.Engines)
			if sc.ScannedAt != nil {
				s += ", scanned " + *sc.ScannedAt
			}
			if sc.ReportURL != nil {
				s += " (report: " + *sc.ReportURL + ")"
			}
			row("virustotal", s)
		}
	}
	if t := r.Trust; t != nil {
		steps := stepStatuses(t.Steps)
		s := fmt.Sprintf("%d of %d checks", t.OK, len(steps))
		if r.Software != nil && r.Software.URL != "" {
			s += "   " + r.Software.URL
		}
		row("fileion", s)
		if len(steps) == len(stepNames) {
			var parts []string
			for i, status := range steps {
				if status == "na" {
					status = "not checked"
				}
				parts = append(parts, stepNames[i]+" "+status)
			}
			row("checks", strings.Join(parts, ", "))
		}
	}
	row("sha256", hash)
}

// cleanItem is the API's item for --json: its own fields, plus the path as typed. Of trust only ok and the steps stay (no label: this
// tool gives no verdict), and the step text uses the name "Installer test".
func cleanItem(raw json.RawMessage, path string) map[string]any {
	m := map[string]any{}
	json.Unmarshal(raw, &m)
	if t, ok := m["trust"].(map[string]any); ok {
		for _, k := range []string{"label", "state", "chip"} {
			delete(t, k)
		}
		var steps []any
		switch v := t["steps"].(type) {
		case []any:
			steps = v
		case map[string]any:
			for _, s := range v {
				steps = append(steps, s)
			}
		}
		for _, s := range steps {
			if sm, ok := s.(map[string]any); ok {
				if txt, ok := sm["text"].(string); ok {
					sm["text"] = strings.ReplaceAll(txt, "Clean installer", "Installer test")
				}
			}
		}
	}
	if path != "" {
		m["path"] = path
	}
	return m
}

// title fetches data of GET /software/{slug}.
func title(c *client, o *opts, pos []string, e env, cmd string) (map[string]any, int) {
	if len(pos) != 1 || !slugRe.MatchString(pos[0]) {
		return nil, usageErr(e, cmd+" needs one title address, like: fileion "+cmd+" vlc")
	}
	b, err := c.do("GET", "/software/"+url.PathEscape(pos[0]), nil)
	if err != nil {
		var ce *cliErr
		if errors.As(err, &ce) && ce.code == exitNotFound {
			ce.msg = "no title with the address " + pos[0]
		}
		return nil, fail(e, o, err)
	}
	var d struct {
		Data map[string]any `json:"data"`
	}
	if json.Unmarshal(b, &d) != nil || d.Data == nil {
		return nil, fail(e, o, &cliErr{code: exitAPI, msg: "unexpected answer from the API (not JSON data)"})
	}
	return d.Data, -1
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func cmdInfo(c *client, o *opts, pos []string, e env) int {
	d, code := title(c, o, pos, e, "info")
	if d == nil {
		return code
	}
	if o.json {
		printJSON(e, o, d)
		return exitOK
	}
	out(e, o, "%s (%s)\n", str(d, "name"), str(d, "slug"))
	row := func(k, v string) {
		if v != "" {
			out(e, o, "  %-12s%s\n", k, v)
		}
	}
	if p, ok := d["publisher"].(map[string]any); ok {
		row("publisher", str(p, "name"))
	}
	var plats []string
	if l, ok := d["platforms"].([]any); ok {
		for _, p := range l {
			plats = append(plats, fmt.Sprint(p))
		}
	}
	row("platforms", strings.Join(plats, ", "))
	row("licence", str(d, "license"))
	row("website", str(d, "website"))
	row("page", str(d, "url"))
	return exitOK
}

func cmdLatest(c *client, o *opts, pos []string, e env) int {
	d, code := title(c, o, pos, e, "latest")
	if d == nil {
		return code
	}
	latest := map[string]any{}
	all, _ := d["latest"].(map[string]any)
	for k, v := range all {
		if v != nil && (o.platform == "" || k == strings.ToLower(o.platform)) {
			latest[k] = v
		}
	}
	if o.platform != "" && len(latest) == 0 {
		return fail(e, o, &cliErr{code: exitNotFound, apiCode: "not_found", msg: fmt.Sprintf("no version of %s for %s", pos[0], o.platform)})
	}
	if o.json {
		printJSON(e, o, latest)
		return exitOK
	}
	names := make([]string, 0, len(latest))
	for k := range latest {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v, _ := latest[k].(map[string]any)
		if o.platform != "" {
			out(e, o, "%s\n", str(v, "version"))
		} else {
			out(e, o, "%-9s %s  %s\n", k, str(v, "version"), str(v, "released_at"))
		}
	}
	return exitOK
}
