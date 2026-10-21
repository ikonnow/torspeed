// torspeed – visible speed + the fastest exits for any local Tor daemon.
// Pure Go stdlib, zero runtime dependencies. Everything runs on 127.0.0.1.
//
//	torspeed             one-shot speed test through the current circuit
//	torspeed --hunt      test the fastest exits + pin the winner
//	                     (Ctrl+C = stop & keep the best found so far)
//	torspeed --serve     local API + dashboard at http://127.0.0.1:8765
//	torspeed -w          live throughput    |  -c  circuits
//	torspeed --exit X    pin an exit        |  --unpin  random selection
//	torspeed --open      launch a browser with a Tor window
//	torspeed --install-ext   write browser extension + instructions
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	fURL     = flag.String("u", "", "extra test URL (tried first)")
	fCands   = flag.Int("candidates", 8, "max exit candidates per hunt")
	fSamples = flag.Int("samples", 2, "measurements per exit candidate (averaged, fresh circuit each)")
	fTarget  = flag.Float64("target", 0, "hunt: target Mbit/s – pin+stop as soon as an exit reaches it")
	fHunt    = flag.Bool("hunt", false, "test the fastest exits + pin the winner")
	fWatch   = flag.Bool("w", false, "live throughput of the Tor daemon")
	fCirc    = flag.Bool("c", false, "show active circuits")
	fExit    = flag.String("exit", "", "pin a specific exit (name/fingerprint)")
	fUnpin   = flag.Bool("unpin", false, "remove exit pinning")
	fOpen    = flag.Bool("open", false, "launch a browser with a Tor window")
	fServe   = flag.Bool("serve", false, "local API + dashboard (extension backend)")
	fPort    = flag.Int("port", 8765, "port for --serve (the extension expects 8765)")
	fInstX   = flag.Bool("install-ext", false, "write browser extension + instructions")
	fMaxMB   = flag.Int64("maxmb", 20, "max MB per speed test")
	fStartT  = flag.Bool("start-tor", false, "start own Tor daemon (needs 'tor' in PATH)")
	fProxy   = flag.Bool("proxy", false, "set the system SOCKS proxy to Tor (macOS/GNOME)")
	fNoProxy = flag.Bool("noproxy", false, "turn the system proxy off again")
	fCompare = flag.Bool("compare", false, "measure all Tor daemons against each other")
	fVer     = flag.Bool("version", false, "print version and exit")
)

// version is set via -ldflags "-X main.version=..."; "dev" for local builds.
var version = "dev"

// ---------- Tor control client ----------

type ctrl struct {
	conn net.Conn
	r    *bufio.Reader
}

func isDigits(s string) bool {
	for _, b := range s {
		if b < '0' || b > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (c *ctrl) cmd(s string) ([]string, error) {
	// Deadline against hung control reads (e.g. ns/all during tor startup);
	// cleared afterwards so event streams (BW) may run unbounded.
	c.conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	if _, err := c.conn.Write([]byte(s + "\r\n")); err != nil {
		return nil, err
	}
	return c.readReply()
}

func (c *ctrl) readReply() ([]string, error) {
	var out []string
	inBlock := false
	for {
		l, err := c.r.ReadString('\n')
		if err != nil {
			return out, err
		}
		l = strings.TrimRight(l, "\r\n")
		if inBlock {
			out = append(out, l)
			if l == "." {
				inBlock = false
			}
			continue
		}
		out = append(out, l)
		if strings.HasPrefix(l, "250+") {
			inBlock = true
			continue
		}
		if len(l) >= 4 && l[3] == ' ' && isDigits(l[:3]) {
			return out, nil
		}
	}
}

// getinfo returns the data lines of a GETINFO (strips 250+/- prefixes).
func (c *ctrl) getinfo(key string) ([]string, error) {
	lines, err := c.cmd("GETINFO " + key)
	var out []string
	inData := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "250+"):
			inData = true
			if i := strings.Index(l, "="); i >= 0 && i+1 < len(l) {
				out = append(out, l[i+1:])
			}
		case strings.HasPrefix(l, "250-"):
			if i := strings.Index(l, "="); i >= 0 {
				out = append(out, l[i+1:])
			}
		case strings.HasPrefix(l, "250 "):
		case inData && l == ".":
			inData = false
		default:
			out = append(out, l)
		}
	}
	return out, err
}

func (c *ctrl) readLine() (string, error) {
	l, err := c.r.ReadString('\n')
	return strings.TrimRight(l, "\r\n"), err
}

func (c *ctrl) close() { c.conn.Close() }

// ---------- Daemon discovery ----------

type daemon struct {
	addr       string // 127.0.0.1:PORT (control port)
	name       string // Brave-Tor, Tor Browser, system tor …
	cookieFile string
	safecookie bool
	socks      string // resolved SOCKS listener (server resolve only)
	ready      bool   // circuit-established == "1" (server resolve only)
}

func braveTorWatch() string {
	home, _ := os.UserHomeDir()
	var pats []string
	switch runtime.GOOS {
	case "windows":
		pats = []string{filepath.Join(os.Getenv("LOCALAPPDATA"),
			"BraveSoftware", "Brave-Browser*", "User Data")}
	case "darwin":
		pats = []string{filepath.Join(home, "Library", "Application Support",
			"BraveSoftware", "Brave-Browser*")}
	default:
		pats = []string{
			filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser*"),
			filepath.Join(home, ".var", "app", "com.brave.Browser", "config",
				"BraveSoftware", "Brave-Browser*"),
		}
	}
	for _, pat := range pats {
		for _, d := range filepathGlob(pat) {
			if fileExists(filepath.Join(d, "tor", "watch", "controlport")) {
				return filepath.Join(d, "tor", "watch")
			}
		}
	}
	return ""
}

func filepathGlob(pat string) []string {
	m, _ := filepath.Glob(pat)
	return m
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// probeDaemon checks a control port and returns the daemon, or nil.
func probeDaemon(addr string) *daemon {
	conn, err := net.DialTimeout("tcp", addr, 700*time.Millisecond)
	if err != nil {
		return nil
	}
	c := &ctrl{conn, bufio.NewReader(conn)}
	lines, err := c.cmd("PROTOCOLINFO")
	if err != nil || len(lines) == 0 ||
		!strings.HasPrefix(lines[0], "250-PROTOCOLINFO") {
		conn.Close()
		return nil
	}
	d := &daemon{addr: addr}
	for _, l := range lines {
		if !strings.HasPrefix(l, "250-AUTH") {
			continue
		}
		if i := strings.Index(l, `COOKIEFILE="`); i >= 0 {
			d.cookieFile = l[i+12 : i+12+strings.Index(l[i+12:], `"`)]
		}
		d.safecookie = strings.Contains(l, "SAFECOOKIE")
	}
	c.close()
	return d
}

// discoverAll finds every reachable Tor daemon (Brave, Tor Browser,
// own/system tor) – they can be raced against each other.
func discoverAll() []*daemon {
	type cand struct{ addr, name string }
	var cands []cand
	if w := braveTorWatch(); w != "" {
		if b, err := os.ReadFile(filepath.Join(w, "controlport")); err == nil {
			if i := strings.Index(string(b), "127.0.0.1:"); i >= 0 {
				cands = append(cands, cand{
					strings.TrimSpace(string(b)[i:]), "Brave-Tor"})
			}
		}
	}
	cands = append(cands,
		cand{"127.0.0.1:9151", "Tor Browser"},
		cand{"127.0.0.1:9051", "System-Tor"})
	var out []*daemon
	seen := map[string]bool{}
	for _, cd := range cands {
		if seen[cd.addr] {
			continue
		}
		seen[cd.addr] = true
		if d := probeDaemon(cd.addr); d != nil {
			d.name = cd.name
			out = append(out, d)
		}
	}
	return out
}

func discover() (*daemon, error) {
	if ds := discoverAll(); len(ds) > 0 {
		return ds[0], nil
	}
	return nil, errors.New("no Tor control port found " +
		"(Tor window/browser open?)")
}

func (d *daemon) connect() (*ctrl, error) {
	conn, err := net.DialTimeout("tcp", d.addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	c := &ctrl{conn, bufio.NewReader(conn)}
	if d.cookieFile == "" {
		if _, err := c.cmd("AUTHENTICATE"); err != nil {
			conn.Close()
			return nil, err
		}
		return c, nil
	}
	cookie, err := os.ReadFile(d.cookieFile)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Prefer SAFECOOKIE (plain COOKIE is deprecated).
	if d.safecookie {
		if err := d.authSafe(c, cookie); err == nil {
			return c, nil
		}
	}
	resp, err := c.cmd("AUTHENTICATE " + hex.EncodeToString(cookie))
	if err != nil || len(resp) == 0 || !strings.HasPrefix(resp[len(resp)-1], "250") {
		conn.Close()
		return nil, errors.New("control auth failed")
	}
	return c, nil
}

func (d *daemon) authSafe(c *ctrl, cookie []byte) error {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	resp, err := c.cmd("AUTHCHALLENGE SAFECOOKIE " + hex.EncodeToString(nonce))
	if err != nil {
		return err
	}
	var snonce []byte
	for _, l := range resp {
		if i := strings.Index(l, "SERVERNONCE="); i >= 0 {
			snonce, _ = hex.DecodeString(l[i+12:])
		}
	}
	if len(snonce) == 0 {
		return errors.New("no SERVERNONCE")
	}
	h := hmac.New(sha256.New,
		[]byte("Tor safe cookie authentication controller-to-server hash"))
	h.Write(append(append(cookie, nonce...), snonce...))
	resp, err = c.cmd("AUTHENTICATE " + hex.EncodeToString(h.Sum(nil)))
	if err != nil || len(resp) == 0 || !strings.HasPrefix(resp[len(resp)-1], "250") {
		return errors.New("SAFECOOKIE failed")
	}
	return nil
}

func socksAddr(c *ctrl) (string, error) {
	lines, err := c.getinfo("net/listeners/socks")
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if i := strings.Index(l, `"127.0.0.1:`); i >= 0 {
			return strings.Trim(l[i:], `"`), nil
		}
	}
	return "", errors.New("no SOCKS listener")
}

// ---------- SOCKS5 (RFC 1928) ----------

// dialSocks opens a SOCKS5 connection to dest via socks. user != "" selects
// username/password auth (RFC 1929, password "x") – Tor's default
// IsolateSOCKSAuth gives every distinct username its own circuit.
func dialSocks(ctx context.Context, socks, user, dest string) (net.Conn, error) {
	d := net.Dialer{Timeout: 20 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", socks)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (net.Conn, error) { conn.Close(); return nil, e }

	buf := make([]byte, 2)
	if user != "" {
		if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
			return fail(err)
		}
		if _, err = io.ReadFull(conn, buf); err != nil || buf[1] != 2 {
			return fail(errors.New("SOCKS auth method refused"))
		}
		u := []byte(user)
		if len(u) > 255 {
			return fail(errors.New("SOCKS username too long"))
		}
		auth := append(append([]byte{1, byte(len(u))}, u...), 1, 'x')
		if _, err = conn.Write(auth); err != nil {
			return fail(err)
		}
		if _, err = io.ReadFull(conn, buf); err != nil ||
			buf[0] != 1 || buf[1] != 0 {
			return fail(errors.New("SOCKS username auth failed"))
		}
	} else {
		if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
			return fail(err)
		}
		if _, err = io.ReadFull(conn, buf); err != nil || buf[1] != 0 {
			return fail(errors.New("SOCKS handshake refused"))
		}
	}
	host, ps, err := net.SplitHostPort(dest)
	if err != nil {
		return fail(err)
	}
	port, _ := strconv.Atoi(ps)
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(append(req, 1), v4...)
		} else {
			req = append(append(req, 4), ip.To16()...)
		}
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err = conn.Write(req); err != nil {
		return fail(err)
	}
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return fail(err)
	}
	if hdr[1] != 0 {
		return fail(fmt.Errorf("SOCKS connect error 0x%02x", hdr[1]))
	}
	var skip int
	switch hdr[3] {
	case 1:
		skip = 4
	case 3:
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		skip = int(lb[0])
	case 4:
		skip = 16
	}
	io.CopyN(io.Discard, conn, int64(skip+2))
	return conn, nil
}

// ---------- Speed test ----------

const (
	probeMaxDur      = 10 * time.Second // transfer-phase limit, from first byte
	probeTTFBTimeout = 12 * time.Second // per URL: request start → first byte
)

// Fallback test URLs: a dead test host would otherwise look like dead exits.
// Large files only – multi-stream probes need headroom. German servers
// first: most exits sit in DE/NL.
var testURLs = []string{
	"https://fsn1-speed.hetzner.com/100MB.bin",
	"https://nbg1-speed.hetzner.com/100MB.bin",
	"https://ash-speed.hetzner.com/100MB.bin",
	"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.9.tar.xz",
	"http://ipv4.download.thinkbroadband.com/20MB.zip",
	"http://speedtest.tele2.net/5MB.zip",
}

type probeOpts struct {
	socks   string        // SOCKS5 address; "" = direct connection (baseline)
	isolate string        // SOCKS username → Tor builds a dedicated fresh circuit ("" = none)
	urls    []string      // tried in order until one delivers data
	maxMB   int64         // total byte budget in MB (1e6 bytes)
	maxDur  time.Duration // 0 → probeMaxDur
	streams int
	label   string
	prog    func(label string, mbps float64) // windowed rate
}

type probeResult struct {
	mbps  float64       // steady-state throughput (excludes setup + slow start)
	ttfb  time.Duration // request start → first byte
	bytes int64
	url   string // URL that delivered data
}

// testURLList returns the user URL first (if non-empty), then the fallback
// test URLs, deduplicated.
func testURLList(user string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range append([]string{user}, testURLs...) {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// isolationToken returns a random SOCKS username; Tor's IsolateSOCKSAuth
// gives every distinct username its own fresh circuit.
func isolationToken() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type snap struct {
	t time.Time
	n int64
}

// speedTest downloads through socks ("" = direct) with o.streams parallel
// streams. The reported rate is steady-state only: the measurement window
// starts after the first byte plus a slow-start grace period, so circuit
// build, TLS handshake, TTFB and Tor congestion control do not skew the
// result towards low latency instead of throughput.
func speedTest(ctx context.Context, o probeOpts) (probeResult, error) {
	var res probeResult
	if o.maxDur <= 0 {
		o.maxDur = probeMaxDur
	}
	if o.streams <= 0 {
		o.streams = 1
	}
	tr := &http.Transport{
		DisableCompression:  true,
		MaxIdleConnsPerHost: o.streams, // re-requests reuse connections
	}
	if o.socks != "" {
		tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialSocks(ctx, o.socks, o.isolate, addr)
		}
	}
	defer tr.CloseIdleConnections()
	// No client-wide Timeout – everything is ctx-driven.
	client := &http.Client{Transport: tr}
	budget := o.maxMB * 1e6

	var total int64   // bytes received so far (atomic)
	var t0Nano int64  // first-byte time, unix nano (atomic, 0 = none yet)
	var t0Bytes int64 // counter value just before the first byte's read
	pastDur := func() bool {
		t0 := atomic.LoadInt64(&t0Nano)
		return t0 != 0 && time.Since(time.Unix(0, t0)) > o.maxDur
	}

	// Sampler: snapshots every 250 ms; from t0+1 s on, prog gets the
	// windowed rate (last ~2 s) every 500 ms. Stopped and joined before
	// return: prog is never called afterwards and no goroutine leaks.
	var snapMu sync.Mutex
	var snaps []snap
	sdone := make(chan struct{})
	var swg sync.WaitGroup
	swg.Add(1)
	go func() {
		defer swg.Done()
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		n := 0
		for {
			select {
			case <-sdone:
				return
			case now := <-tick.C:
				t0 := atomic.LoadInt64(&t0Nano)
				if t0 == 0 {
					continue
				}
				cur := atomic.LoadInt64(&total)
				snapMu.Lock()
				snaps = append(snaps, snap{now, cur})
				snapMu.Unlock()
				n++
				if o.prog == nil || n%2 != 0 ||
					now.Sub(time.Unix(0, t0)) < time.Second {
					continue
				}
				snapMu.Lock()
				old := snaps[0]
				cutoff := now.Add(-2 * time.Second)
				for _, s := range snaps {
					if !s.t.Before(cutoff) {
						old = s
						break
					}
				}
				snapMu.Unlock()
				if dt := now.Sub(old.t).Seconds(); dt > 0 {
					o.prog(o.label, float64(cur-old.n)*8/dt/1e6)
				}
			}
		}
	}()

	// Worker: GET loop until the byte budget, maxDur (counted from the
	// first byte) or ctx ends it. io.EOF with budget/time left →
	// re-request (small files must still saturate); other errors end
	// only this stream.
	var wg sync.WaitGroup
	first := make(chan struct{})
	var onceFirst sync.Once
	worker := func(wctx context.Context, u string) {
		defer wg.Done()
		for wctx.Err() == nil && atomic.LoadInt64(&total) < budget &&
			!pastDur() {
			req, _ := http.NewRequestWithContext(wctx, "GET", u, nil)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			if resp.StatusCode != 200 && resp.StatusCode != 206 {
				resp.Body.Close()
				return
			}
			buf := make([]byte, 256*1024)
			for {
				m, e := resp.Body.Read(buf)
				if m > 0 {
					before := atomic.AddInt64(&total, int64(m)) - int64(m)
					if atomic.LoadInt64(&t0Nano) == 0 {
						t0Bytes = before
						atomic.StoreInt64(&t0Nano, time.Now().UnixNano())
						onceFirst.Do(func() { close(first) })
					}
				}
				if e == io.EOF {
					break
				}
				if e != nil {
					resp.Body.Close()
					return
				}
				if atomic.LoadInt64(&total) >= budget || pastDur() {
					break
				}
			}
			resp.Body.Close()
		}
	}

	// Phase 1: find a URL that delivers data. Stream 1 alone gets the
	// TTFB window; the moment its first byte lands, the rest join in.
	var s1cancel context.CancelFunc
	for _, u := range o.urls {
		if ctx.Err() != nil {
			break
		}
		var sctx context.Context
		sctx, s1cancel = context.WithCancel(ctx)
		w1done := make(chan struct{})
		reqStart := time.Now()
		wg.Add(1)
		go func() { defer close(w1done); worker(sctx, u) }()
		timer := time.NewTimer(probeTTFBTimeout)
		select {
		case <-first:
			timer.Stop()
		case <-w1done:
			timer.Stop()
			s1cancel()
		case <-timer.C:
			s1cancel()
			<-w1done
		case <-ctx.Done():
			timer.Stop()
			s1cancel()
			<-w1done
		}
		if atomic.LoadInt64(&t0Nano) != 0 {
			res.url = u
			res.ttfb = time.Unix(0, atomic.LoadInt64(&t0Nano)).Sub(reqStart)
			break
		}
	}
	// Phase 2: the remaining streams join on the working URL. A hard
	// deadline at t0+maxDur bounds the transfer phase even if a read
	// stalls while ctx is context.Background().
	if res.url != "" {
		t0 := time.Unix(0, atomic.LoadInt64(&t0Nano))
		pctx, pcancel := context.WithDeadline(ctx, t0.Add(o.maxDur))
		defer pcancel()
		for i := 1; i < o.streams; i++ {
			wg.Add(1)
			go worker(pctx, res.url)
		}
		time.AfterFunc(o.maxDur, s1cancel)
	}
	wg.Wait()
	if s1cancel != nil {
		s1cancel()
	}
	close(sdone)
	swg.Wait()

	res.bytes = atomic.LoadInt64(&total)
	tEnd := time.Now()
	if res.url == "" {
		return res, errors.New("all test URLs failed")
	}
	// Steady state: skip the first w seconds (circuit build / TLS / TTFB
	// + congestion-control slow start), then divide the bytes received
	// after t0+w by the remaining span.
	t0 := time.Unix(0, atomic.LoadInt64(&t0Nano))
	span := tEnd.Sub(t0)
	w := span / 3
	if w > 1500*time.Millisecond {
		w = 1500 * time.Millisecond
	}
	snapMu.Lock()
	var cut *snap
	for i := range snaps {
		if !snaps[i].t.Before(t0.Add(w)) {
			cut = &snaps[i]
			break
		}
	}
	snapMu.Unlock()
	if cut != nil && span > w {
		res.mbps = float64(res.bytes-cut.n) * 8 / (span - w).Seconds() / 1e6
	} else if span > 0 {
		res.mbps = float64(res.bytes-t0Bytes) * 8 / span.Seconds() / 1e6
	}
	return res, nil
}

// ---------- Consensus / candidates ----------

type relay struct {
	fp, name      string
	bw            int // KiB/s
	exit, running bool
	pol           string
}

func parseConsensus(lines []string) []relay {
	var rs []relay
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "r "):
			f := strings.Fields(l)
			if len(f) < 3 {
				continue
			}
			raw, err := base64.RawStdEncoding.DecodeString(f[2])
			fp := ""
			if err == nil {
				fp = strings.ToUpper(hex.EncodeToString(raw))
			}
			rs = append(rs, relay{fp: fp, name: f[1]})
		case strings.HasPrefix(l, "s ") && len(rs) > 0:
			fl := " " + l[2:] + " "
			rs[len(rs)-1].exit = strings.Contains(fl, " Exit ") &&
				!strings.Contains(fl, " BadExit ")
			rs[len(rs)-1].running = strings.Contains(fl, " Running ")
		case strings.HasPrefix(l, "w ") && len(rs) > 0:
			if i := strings.Index(l, "Bandwidth="); i >= 0 {
				rs[len(rs)-1].bw, _ = strconv.Atoi(
					strings.Fields(l[i+10:])[0])
			}
		case strings.HasPrefix(l, "p ") && len(rs) > 0:
			rs[len(rs)-1].pol = l[2:]
		}
	}
	return rs
}

// coversPort reports whether an exit policy summary ("p …") allows port.
func coversPort(pol string, port int) bool {
	f := strings.Fields(pol)
	if len(f) < 2 {
		return false
	}
	covers := func(p int) bool {
		for _, r := range strings.Split(f[1], ",") {
			if r == "*" || r == "*:*" {
				return true
			}
			lo, hi := r, r
			if i := strings.Index(r, "-"); i >= 0 {
				lo, hi = r[:i], r[i+1:]
			}
			a, _ := strconv.Atoi(lo)
			b, _ := strconv.Atoi(hi)
			if a <= p && p <= b {
				return true
			}
		}
		return false
	}
	if f[0] == "accept" {
		return covers(port)
	}
	return !covers(port)
}

// topExits returns the n highest-bandwidth usable exits. Browsing needs
// both web ports, so the exit policy must cover 80 AND 443. Clients using
// microdescriptors get no "p" line in ns/all – those relays are checked
// lazily via GETINFO md/id/<fp> (error or missing p → keep, as before),
// which avoids pinning exits that reject web traffic.
func topExits(c *ctrl, n int) ([]relay, error) {
	lines, err := c.getinfo("ns/all")
	if err != nil {
		return nil, err
	}
	var ok []relay
	for _, r := range parseConsensus(lines) {
		if !r.exit || !r.running || r.fp == "" {
			continue
		}
		if r.pol != "" && !(coversPort(r.pol, 80) && coversPort(r.pol, 443)) {
			continue
		}
		ok = append(ok, r)
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].bw > ok[j].bw })
	var out []relay
	for _, r := range ok {
		if len(out) >= n {
			break
		}
		if r.pol == "" {
			if md, err := c.getinfo("md/id/" + r.fp); err == nil {
				for _, l := range md {
					if strings.HasPrefix(l, "p ") {
						r.pol = l[2:]
						break
					}
				}
			}
			if r.pol != "" &&
				!(coversPort(r.pol, 80) && coversPort(r.pol, 443)) {
				continue
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// ---------- Pin / circuits ----------

// StrictNodes does not apply to ExitNodes (exit circuits are always
// strict) – touching it would only clobber the user's ExcludeNodes
// strictness, so pin/unpin only manage ExitNodes.
func pin(c *ctrl, fp string) {
	c.cmd("SETCONF ExitNodes=$" + fp)
}

func unpin(c *ctrl) {
	c.cmd("RESETCONF ExitNodes")
}

// exitFP returns the exit relay fingerprint of a BUILT general-purpose
// circuit-status line, or "" for anything else (HS circuits, still
// extending, malformed).
func exitFP(l string) string {
	f := strings.Fields(l)
	if len(f) < 3 || f[1] != "BUILT" {
		return ""
	}
	purpose := ""
	for _, kv := range f[3:] {
		if p, ok := strings.CutPrefix(kv, "PURPOSE="); ok {
			purpose = p
			break
		}
	}
	if purpose != "GENERAL" && purpose != "CONFLUX_LINKED" {
		return ""
	}
	path := strings.Split(f[2], ",")
	last := strings.TrimPrefix(path[len(path)-1], "$")
	if i := strings.Index(last, "~"); i >= 0 {
		last = last[:i]
	}
	return last
}

// closeStaleCircuits kills BUILT general-purpose circuits whose LAST hop
// is not keepFP. ExitNodes/NEWNYM only affect NEW streams – keep-alive
// and HTTP/2 connections would linger on the old exit otherwise, so a
// freshly pinned exit would not take effect in open tabs. Hidden-service
// and still-extending circuits are never touched.
func closeStaleCircuits(c *ctrl, keepFP string) int {
	lines, _ := c.getinfo("circuit-status")
	n := 0
	for _, l := range lines {
		fp := exitFP(l)
		if fp == "" || strings.EqualFold(fp, keepFP) {
			continue
		}
		if r, err := c.cmd("CLOSECIRCUIT " + strings.Fields(l)[0]); err == nil &&
			len(r) > 0 && strings.HasPrefix(r[len(r)-1], "250") {
			n++
		}
	}
	return n
}

// lastCircuitExit returns the exit fingerprint of the newest BUILT
// general-purpose circuit – what a new request would most likely exit
// through. "" when nothing is built yet (e.g. freshly started daemon).
func lastCircuitExit(c *ctrl) string {
	fp := ""
	lines, _ := c.getinfo("circuit-status")
	for _, l := range lines {
		if e := exitFP(l); e != "" {
			fp = e
		}
	}
	return fp
}

// relayInfo resolves a fingerprint via ns/id: nickname + OR address
// (the r line reads: name id digest date time ip orport dirport).
func relayInfo(c *ctrl, fp string) (name, ip string) {
	lines, err := c.getinfo("ns/id/" + fp)
	if err != nil {
		return "", ""
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "r ") {
			if f := strings.Fields(l); len(f) > 6 {
				return f[1], f[6]
			}
			break
		}
	}
	return "", ""
}

// spawnTor launches a dedicated Tor daemon (SOCKS 9050, control 9051,
// cookie auth). The browser can then surf via proxy settings directly
// over Tor – no Tor Browser window needed.
func spawnTor() error {
	exe, err := exec.LookPath("tor")
	if err != nil {
		for _, p := range []string{"/opt/homebrew/bin/tor",
			"/usr/local/bin/tor", "/usr/bin/tor"} {
			if _, e := os.Stat(p); e == nil {
				exe = p
				break
			}
		}
	}
	if exe == "" {
		return errors.New("tor binary not found – install first: brew install tor")
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".torspeed", "tor")
	os.MkdirAll(dir, 0700)
	// --RunAsDaemon forks cleanly into the background.
	cmd := exec.Command(exe,
		"--SocksPort", "127.0.0.1:9050",
		"--ControlPort", "127.0.0.1:9051",
		"--CookieAuthentication", "1",
		"--DataDirectory", dir,
		"--RunAsDaemon", "1",
		"--Log", "notice file "+filepath.Join(dir, "tor.log"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tor start: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------- System proxy (SOCKS) ----------
// Not a kernel-level redirect (macOS pf cannot do outbound redirects) –
// but every proxy-aware app then runs through Tor. On macOS via
// networksetup, on GNOME via gsettings.

func proxyService() (string, error) {
	out, err := exec.Command("route", "get", "-inet", "default").Output()
	if err != nil {
		return "", err
	}
	dev := ""
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "interface:") {
			dev = strings.TrimSpace(strings.TrimPrefix(l, "interface:"))
		}
	}
	if dev == "" {
		return "", errors.New("no default interface")
	}
	// Map hardware port -> service name ("Wi-Fi" etc.) via device.
	out, err = exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return "", err
	}
	blocks := strings.Split(string(out), "Hardware Port: ")
	for _, b := range blocks[1:] {
		lines := strings.Split(b, "\n")
		name := strings.TrimSpace(lines[0])
		for _, l := range lines[1:] {
			if strings.Contains(l, "Device: "+dev) {
				return name, nil
			}
		}
	}
	return "Wi-Fi", nil // fallback: most common service name
}

// proxySetFn is a variable so tests can stub out the real system change.
var proxySetFn = proxySet

func proxySet(on bool, socksAddr string) error {
	proxyStateInvalidate()
	if runtime.GOOS == "darwin" {
		svc, err := proxyService()
		if err != nil {
			return err
		}
		if on {
			host, port, _ := net.SplitHostPort(socksAddr)
			if host == "" {
				host = "127.0.0.1"
			}
			if port == "" {
				port = "9050"
			}
			if err := exec.Command("networksetup", "-setsocksfirewallproxy",
				svc, host, port).Run(); err != nil {
				return fmt.Errorf("networksetup proxy: %w", err)
			}
			err = exec.Command("networksetup", "-setsocksfirewallproxystate",
				svc, "on").Run()
			return err
		}
		return exec.Command("networksetup", "-setsocksfirewallproxystate",
			svc, "off").Run()
	}
	// GNOME/Linux.
	if runtime.GOOS == "linux" {
		if on {
			host, port, _ := net.SplitHostPort(socksAddr)
			for _, c := range [][]string{
				{"set", "org.gnome.system.proxy.socks", "host", host},
				{"set", "org.gnome.system.proxy.socks", "port", port},
				{"set", "org.gnome.system.proxy", "mode", "manual"},
			} {
				exec.Command("gsettings", c...).Run()
			}
			return nil
		}
		return exec.Command("gsettings", "set",
			"org.gnome.system.proxy", "mode", "none").Run()
	}
	return errors.New("OS not supported – set the proxy manually")
}

// proxyStateProbe is the uncached OS probe – a variable so tests can stub
// it (the real probe shells out to route/networksetup/gsettings).
var proxyStateProbe = func() bool {
	if runtime.GOOS == "darwin" {
		svc, err := proxyService()
		if err != nil {
			return false
		}
		out, _ := exec.Command("networksetup", "-getsocksfirewallproxy",
			svc).Output()
		return strings.Contains(string(out), "Enabled: Yes")
	}
	if runtime.GOOS == "linux" {
		out, _ := exec.Command("gsettings", "get",
			"org.gnome.system.proxy", "mode").Output()
		return strings.Contains(string(out), "manual")
	}
	return false
}

// proxyPortProbe reads the port the system proxy is currently pointed at
// – a variable so tests can stub it. Returns "" when unknown.
var proxyPortProbe = func() string {
	if runtime.GOOS == "darwin" {
		svc, err := proxyService()
		if err != nil {
			return ""
		}
		out, _ := exec.Command("networksetup",
			"-getsocksfirewallproxy", svc).Output()
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "Port:") {
				return strings.TrimSpace(strings.TrimPrefix(l, "Port:"))
			}
		}
	}
	if runtime.GOOS == "linux" {
		out, err := exec.Command("gsettings", "get",
			"org.gnome.system.proxy.socks", "port").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

// proxyStateTTL caches the proxy state – every /api/status poll would
// otherwise spawn route + 2× networksetup.
const proxyStateTTL = 30 * time.Second

var proxyStateCache struct {
	mu  sync.Mutex
	at  time.Time
	on  bool
	set bool
}

func proxyStateInvalidate() {
	proxyStateCache.mu.Lock()
	proxyStateCache.set = false
	proxyStateCache.mu.Unlock()
}

func proxyState() bool {
	proxyStateCache.mu.Lock()
	defer proxyStateCache.mu.Unlock()
	if proxyStateCache.set && time.Since(proxyStateCache.at) < proxyStateTTL {
		return proxyStateCache.on
	}
	proxyStateCache.on = proxyStateProbe()
	proxyStateCache.at = time.Now()
	proxyStateCache.set = true
	return proxyStateCache.on
}

func pinnedExit(c *ctrl) string {
	lines, _ := c.cmd("GETCONF ExitNodes")
	for _, l := range lines {
		if i := strings.Index(l, "ExitNodes="); i >= 0 {
			return strings.TrimPrefix(l[i+10:], "$")
		}
	}
	return ""
}

func showCircuits(c *ctrl) {
	lines, _ := c.getinfo("circuit-status")
	n := 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		n++
		var hops []string
		for _, h := range strings.Split(f[2], ",") {
			if i := strings.Index(h, "~"); i >= 0 {
				hops = append(hops, h[i+1:])
			} else {
				hops = append(hops, strings.TrimPrefix(h, "$")[:8])
			}
		}
		fmt.Printf("  #%-4s %-10s %s\n", f[0], f[1], strings.Join(hops, " -> "))
	}
	if n == 0 {
		fmt.Println("  (no active circuits)")
	}
	if p := pinnedExit(c); p != "" {
		fmt.Printf("\nPinned exit: %s\n", p)
	}
}

// ---------- Hunt ----------

func bar(v, max float64, w int) string {
	if max <= 0 {
		max = 25
	}
	fill := int(v / max * float64(w))
	if fill > w {
		fill = w
	}
	return "[" + strings.Repeat("#", fill) + strings.Repeat("-", w-fill) + "]"
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// hunt tests top exits and pins the best. logf receives every line (UI/SSE).
func hunt(ctx context.Context, d *daemon, target float64, candidates int,
	url string, maxMB int64, samples int,
	logf func(string), prog func(string, float64),
	onBest func(string, float64)) (bestFP, bestName string, bestMbps float64) {

	c, err := d.connect()
	if err != nil {
		logf("control connection: " + err.Error())
		return
	}
	defer c.close()
	socks, err := socksAddr(c)
	if err != nil {
		logf("SOCKS: " + err.Error())
		return
	}
	logf("Loading consensus …")
	// Pool instead of a fixed top-N: consensus bandwidth does not correlate
	// with congestion – the fastest exits are the most contested ones.
	// `candidates` candidates are drawn randomly from the top 60.
	var pool []relay
	for a := 0; a < 6; a++ {
		pool, err = topExits(c, 60)
		if err == nil && len(pool) > 0 {
			break
		}
		if a < 5 {
			logf("tor still starting – waiting for consensus …")
			sleepCtx(ctx, 5*time.Second)
			if ctx.Err() != nil {
				break
			}
		}
	}
	if err != nil || len(pool) == 0 {
		logf("no exits in consensus – tor still starting?")
		return
	}
	mrand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	cands := pool
	if len(cands) > candidates {
		cands = cands[:candidates]
	}
	logf(fmt.Sprintf("%d candidates (random from top-%d)",
		len(cands), len(pool)))
	urls := testURLList(url)
	// After the first successful sample only the known-good URL is used:
	// a candidate that cannot reach it is the exit's fault, not the test
	// host's. Two consecutive such failures → the host may rate-limit,
	// fall back to the full list.
	known := ""
	knownFails := 0
	bestMbps = -1
	for i, r := range cands {
		if ctx.Err() != nil {
			break
		}
		pin(c, r.fp)
		head := fmt.Sprintf("[%d/%d] %-20s weight %6d ",
			i+1, len(cands), r.name, r.bw)
		sampleURLs := urls
		if known != "" {
			sampleURLs = []string{known}
		}
		var vals []float64
		var lastErr error
		for j := 0; j < samples && ctx.Err() == nil; j++ {
			sctx, scancel := context.WithCancel(ctx)
			var ticks, stable int
			var prev float64
			res, err := speedTest(sctx, probeOpts{
				socks:   socks,
				isolate: isolationToken(), // fresh circuit, new random middle
				urls:    sampleURLs,
				maxMB:   maxMB,
				streams: 3,
				label:   r.name,
				prog: func(name string, v float64) {
					if prog != nil {
						prog(name, v)
					}
					ticks++
					if ticks < 3 {
						return // need ≥2 s of windowed data first
					}
					// clearly worse than the best value → abort the probe
					if bestMbps > 0 && v < bestMbps*0.7 {
						scancel()
						return
					}
					// rate converged → end the download early
					if prev > 0 && math.Abs(v-prev)/v < 0.05 {
						if stable++; stable >= 2 {
							scancel()
						}
					} else {
						stable = 0
					}
					prev = v
				}})
			scancel()
			if err != nil {
				lastErr = err
				if j == 0 {
					break // first sample failed → skip this candidate
				}
				continue
			}
			vals = append(vals, res.mbps)
			if res.url != "" {
				known = res.url
				sampleURLs = []string{known}
			}
		}
		if len(vals) == 0 {
			if ctx.Err() == nil {
				logf(head + fmt.Sprintf("failed (%s)", lastErr))
				if known != "" {
					if knownFails++; knownFails >= 2 {
						known, knownFails = "", 0
						logf("known test URL failing – back to the full list")
					}
				}
				continue
			}
			break
		}
		knownFails = 0
		// Mean of the samples: the browser will use random middles
		// later, so the average is what counts – not a lucky middle.
		var sum float64
		for _, v := range vals {
			sum += v
		}
		mbps := sum / float64(len(vals))
		indiv := make([]string, len(vals))
		for j, v := range vals {
			indiv[j] = fmt.Sprintf("%.1f", v)
		}
		tag := ""
		if mbps > bestMbps {
			bestMbps, bestFP, bestName = mbps, r.fp, r.name
			tag = "  <-- BEST"
			if onBest != nil {
				onBest(r.name, mbps)
			}
		}
		logf(head + fmt.Sprintf("%s %5.1f Mbit/s (%s)%s",
			bar(mbps, target, 12), mbps, strings.Join(indiv, "/"), tag))
		if ctx.Err() != nil || (target > 0 && mbps >= target) {
			break
		}
	}
	if bestFP != "" {
		pin(c, bestFP)
		// Open connections keep the old exit otherwise – kill their
		// circuits so tabs switch to the pinned exit without a reload.
		closed := closeStaleCircuits(c, bestFP)
		c.cmd("SIGNAL NEWNYM")
		sleepCtx(ctx, 4*time.Second)
		verify := ""
		vurls := urls
		if known != "" {
			vurls = []string{known}
		}
		if res, err := speedTest(ctx, probeOpts{
			socks:   socks,
			isolate: isolationToken(),
			urls:    vurls,
			maxMB:   maxMB,
			streams: 3,
			label:   bestName,
			prog:    prog}); err == nil {
			verify = fmt.Sprintf(", verification: %.1f", res.mbps)
		}
		logf(fmt.Sprintf("BEST EXIT PINNED: %s (best %.1f%s Mbit/s) – %d old circuits closed, tabs switch automatically",
			bestName, bestMbps, verify, closed))
	} else {
		unpin(c)
		logf("no usable exit – random selection active.")
	}
	return
}

// ---------- Watch ----------

func watch(d *daemon, ctx context.Context) {
	c, err := d.connect()
	if err != nil {
		fatal(err)
	}
	defer c.close()
	if _, err = c.cmd("SETEVENTS BW"); err != nil {
		fatal(err)
	}
	fmt.Println("Live throughput (all Tor tabs). Ctrl+C stops.")
	for ctx.Err() == nil {
		l, err := c.readLine()
		if err != nil {
			fmt.Println("\nconnection lost.")
			return
		}
		var rd, wr int64
		if n, _ := fmt.Sscanf(l, "650 BW %d %d", &rd, &wr); n == 2 {
			fmt.Printf("\r  DOWN %8.1f Mbit/s   UP %8.1f Mbit/s   ",
				float64(rd)*8/1e6, float64(wr)*8/1e6)
		}
	}
	fmt.Println()
}

// ---------- Browser ----------

func openBrowser() error {
	switch runtime.GOOS {
	case "darwin":
		for _, app := range []string{"Brave Browser", "Tor Browser"} {
			if fileExists("/Applications/" + app + ".app") {
				args := []string{"-a", app}
				if app == "Brave Browser" {
					args = append(args, "--args", "--tor")
				}
				return exec.Command("open", args...).Start()
			}
		}
	case "windows":
		for _, p := range []string{
			`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
			`C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe`,
		} {
			if fileExists(p) {
				return exec.Command(p, "--tor").Start()
			}
		}
	default:
		for _, b := range []string{"brave-browser", "brave", "torbrowser-launcher",
			"start-tor-browser"} {
			if p, err := exec.LookPath(b); err == nil {
				if strings.HasPrefix(b, "brave") {
					return exec.Command(p, "--tor").Start()
				}
				return exec.Command(p).Start()
			}
		}
	}
	return errors.New("no Tor-capable browser found")
}

// ---------- API + dashboard (--serve) ----------

type hub struct {
	mu      sync.Mutex
	clients map[chan string]bool
}

func (h *hub) add() chan string {
	ch := make(chan string, 64)
	h.mu.Lock()
	h.clients[ch] = true
	h.mu.Unlock()
	return ch
}

func (h *hub) drop(ch chan string) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func (h *hub) pub(msg string) {
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
	h.mu.Unlock()
}

type server struct {
	d          *daemon
	daemons    []*daemon
	discAt     time.Time
	dmu        sync.Mutex
	discover   func() []*daemon // injectable (tests); defaults to discoverAll
	hub        *hub
	mu         sync.Mutex
	hunting    bool
	measuring  bool
	cancel     context.CancelFunc
	lastMB     float64
	lastAt     int64 // unix seconds, 0 = never
	bestMB     float64
	bestAt     int64   // unix seconds, 0 = never
	directMB   float64 // baseline speed without Tor (cached)
	directAt   time.Time
	directBusy bool
	// fastest score found so far in the running hunt (gamified display)
	huntBestMB   float64
	huntBestName string
	url          string
	target       float64
	candidates   int
	maxMB        int64
	samples      int
}

// discoverDaemons returns s.discover() or falls back to discoverAll.
func (s *server) discoverDaemons() []*daemon {
	if s.discover != nil {
		return s.discover()
	}
	return discoverAll()
}

// daemon returns the current Tor daemon; dead ports trigger re-discovery
// (Brave spawns tor on demand with a new dynamic port).
func (s *server) daemon() *daemon {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	refresh := len(s.daemons) == 0 || time.Since(s.discAt) > 60*time.Second
	if s.d != nil && !refresh {
		if c, err := net.DialTimeout("tcp", s.d.addr, 400*time.Millisecond); err == nil {
			c.Close()
			return s.d
		}
	}
	s.daemons = s.discoverDaemons()
	s.discAt = time.Now()
	for _, dd := range s.daemons {
		resolveDaemon(dd)
	}
	if len(s.daemons) > 0 {
		// keep current daemon when still reachable
		for _, dd := range s.daemons {
			if s.d != nil && dd.addr == s.d.addr {
				return s.d
			}
		}
		s.d = s.daemons[0]
		go s.logf("tor daemon: %s (%s)", s.d.name, s.d.addr)
		return s.d
	}
	return nil
}

// resolveDaemon fills in d.socks and d.ready via the control port.
// Only used on the server's (re)discovery path – CLI discovery stays fast.
func resolveDaemon(d *daemon) {
	d.socks, d.ready = "", false
	c, err := d.connect()
	if err != nil {
		return
	}
	defer c.close()
	if socks, err := socksAddr(c); err == nil {
		d.socks = socks
	}
	if lines, err := c.getinfo("status/circuit-established"); err == nil &&
		len(lines) > 0 {
		d.ready = strings.TrimSpace(lines[0]) == "1"
	}
}

// proxyCheck re-points the system proxy when the configured port no
// longer belongs to a ready daemon (Tor SOCKS ports – Brave's dynamic
// one! – change across restarts). One iteration; reads the daemon list
// under dmu and does no network I/O besides the OS probes. Fail closed:
// with no ready daemon the current setting is left untouched.
func (s *server) proxyCheck() {
	if !proxyState() {
		return
	}
	cur := proxyPortProbe()
	s.dmu.Lock()
	var active, firstReady *daemon
	for _, dd := range s.daemons {
		_, port, err := net.SplitHostPort(dd.socks)
		if !dd.ready || err != nil {
			continue
		}
		if port == cur {
			s.dmu.Unlock()
			return // already points at a ready daemon
		}
		if firstReady == nil {
			firstReady = dd
		}
		if s.d != nil && dd.addr == s.d.addr {
			active = dd
		}
	}
	s.dmu.Unlock()
	d := active
	if d == nil {
		d = firstReady
	}
	if d == nil {
		return
	}
	if err := proxySetFn(true, d.socks); err == nil {
		s.logf("system proxy re-pointed to %s (%s)", d.name, d.socks)
	}
}

func (s *server) logf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Println(msg)
	s.hub.pub(fmt.Sprintf(`{"type":"log","msg":%q}`, msg))
}

func (s *server) startHunt() {
	s.mu.Lock()
	if s.hunting || s.measuring {
		s.mu.Unlock()
		go s.logf("busy – a hunt or measurement is running")
		return
	}
	d := s.daemon()
	if d == nil {
		s.mu.Unlock()
		go s.logf("no Tor daemon found – Tor window open?")
		return
	}
	s.hunting = true
	s.huntBestMB, s.huntBestName = 0, ""
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.hunting = false
			s.mu.Unlock()
			s.ensureDirect() // refresh the baseline after a hunt
		}()
		_, _, best := hunt(ctx, d, s.target, s.candidates, s.url, s.maxMB, s.samples,
			func(m string) { s.logf("%s", m) },
			func(name string, v float64) {
				s.hub.pub(fmt.Sprintf(`{"type":"prog","v":%.1f,"name":%q}`, v, name))
			},
			s.onHuntBest)
		if best > 0 {
			s.mu.Lock()
			s.bestMB = best
			s.bestAt = time.Now().Unix()
			s.mu.Unlock()
			s.hub.pub(fmt.Sprintf(`{"type":"mbps","v":%.1f}`, best))
		}
	}()
}

// onHuntBest is hunt's onBest callback: records the leading candidate's
// mean and notifies SSE clients so the popup/dashboard can celebrate
// instantly. Live probe ticks reach the display separately (prog events).
func (s *server) onHuntBest(name string, v float64) {
	s.mu.Lock()
	s.huntBestName, s.huntBestMB = name, v
	s.mu.Unlock()
	s.hub.pub(fmt.Sprintf(`{"type":"best","v":%.1f,"name":%q}`, v, name))
}

func (s *server) measure() {
	s.mu.Lock()
	if s.hunting || s.measuring {
		s.mu.Unlock()
		s.logf("busy – a hunt or measurement is running")
		return
	}
	s.measuring = true
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			s.measuring = false
			s.mu.Unlock()
			s.ensureDirect() // refresh the baseline after measuring
		}()
		d := s.daemon()
		if d == nil {
			s.logf("no Tor daemon – Tor window open?")
			return
		}
		c, err := d.connect()
		if err != nil {
			s.logf("control: %v", err)
			return
		}
		defer c.close()
		socks, _ := socksAddr(c)
		s.logf("measuring …")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		res, err := speedTest(ctx, probeOpts{
			socks:   socks,
			urls:    testURLList(s.url),
			maxMB:   s.maxMB,
			streams: 3,
			prog: func(name string, v float64) {
				s.hub.pub(fmt.Sprintf(`{"type":"prog","v":%.1f,"name":%q}`, v, name))
			}})
		if err != nil {
			s.logf("measurement failed: %v", err)
			return
		}
		s.mu.Lock()
		s.lastMB = res.mbps
		s.lastAt = time.Now().Unix()
		s.mu.Unlock()
		s.hub.pub(fmt.Sprintf(`{"type":"mbps","v":%.1f}`, res.mbps))
		s.logf("measured %.1f Mbit/s", res.mbps)
	}()
}

// directMinSpacing bounds the no-Tor baseline probes; the old 120 s poll
// burned ~5 GB/day and competed with Tor probes on the same downlink.
const directMinSpacing = 10 * time.Minute

// ensureDirect measures the no-Tor baseline in the background – never
// while a hunt or measurement is running (it would skew the result).
func (s *server) ensureDirect() {
	s.mu.Lock()
	if s.hunting || s.measuring || s.directBusy ||
		time.Since(s.directAt) < directMinSpacing {
		s.mu.Unlock()
		return
	}
	s.directBusy = true
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// Baseline: fast fallback URLs, 6 streams – comparable to
		// multi-stream speedtests like fast.com.
		res, err := speedTest(ctx, probeOpts{
			urls:    testURLs,
			maxMB:   25,
			maxDur:  5 * time.Second,
			streams: 6})
		s.mu.Lock()
		defer s.mu.Unlock()
		s.directBusy = false
		if err == nil {
			s.directMB = res.mbps
			s.directAt = time.Now()
		}
	}()
}

// compareDaemons measures the daemons SEQUENTIALLY (parallel probes would
// share the downlink and make the comparison unfair) and returns the
// fastest one. Shared by --compare and the /api/compare endpoint.
func compareDaemons(ds []*daemon, url string,
	logf func(string, ...interface{})) (*daemon, float64) {
	var best *daemon
	var bm float64
	for _, d := range ds {
		var m float64
		if c, err := d.connect(); err == nil {
			socks, _ := socksAddr(c)
			c.close()
			if socks != "" {
				ctx, cancel := context.WithTimeout(
					context.Background(), 30*time.Second)
				if res, err := speedTest(ctx, probeOpts{
					socks:   socks,
					isolate: isolationToken(),
					urls:    testURLList(url),
					maxMB:   10,
					streams: 3}); err == nil {
					m = res.mbps
				}
				cancel()
			}
		}
		logf("%s: %.1f Mbit/s", d.name, m)
		if m > bm {
			bm, best = m, d
		}
	}
	return best, bm
}

// compare measures all discovered daemons sequentially – the winner goes active.
func (s *server) compare() {
	s.mu.Lock()
	if s.hunting || s.measuring {
		s.mu.Unlock()
		s.logf("busy – a hunt or measurement is running")
		return
	}
	s.measuring = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.measuring = false
		s.mu.Unlock()
	}()
	s.dmu.Lock()
	ds := s.daemons
	s.dmu.Unlock()
	if len(ds) == 0 {
		ds = s.discoverDaemons()
	}
	if len(ds) == 0 {
		s.logf("no Tor daemons found")
		return
	}
	s.logf("measuring %d daemons sequentially …", len(ds))
	best, bm := compareDaemons(ds, s.url,
		func(f string, a ...interface{}) { s.logf(f, a...) })
	if best != nil && bm > 0 {
		s.dmu.Lock()
		s.d, s.daemons = best, ds
		s.dmu.Unlock()
		s.logf("winner: %s (%.1f) – now active", best.name, bm)
	}
}

func (s *server) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	if r.Method == "OPTIONS" {
		return
	}
	switch r.URL.Path {
	case "/api/status":
		s.mu.Lock()
		needDirect := s.directAt.IsZero()
		hunting, last, best, direct := s.hunting, s.lastMB, s.bestMB, s.directMB
		lastAt, bestAt := s.lastAt, s.bestAt
		huntBestMB, huntBestName := s.huntBestMB, s.huntBestName
		s.mu.Unlock()
		if needDirect {
			s.ensureDirect() // first status poll fills the baseline once
		}
		pin, pinName, socks, exitName, exitIP := "", "", "", "", ""
		if d := s.daemon(); d != nil {
			if c, err := d.connect(); err == nil {
				socks, _ = socksAddr(c)
				pin = pinnedExit(c)
				// the currently seen exit IP: the pin when set, else the
				// exit of the newest built circuit – all locally resolved,
				// no third-party IP check needed.
				fp := pin
				if fp == "" {
					fp = lastCircuitExit(c)
				}
				if fp != "" {
					exitName, exitIP = relayInfo(c, fp)
				}
				if pin != "" {
					pinName = exitName
				}
				c.close()
			}
		}
		dName := ""
		s.dmu.Lock()
		dlist := make([]map[string]interface{}, 0, len(s.daemons))
		for _, dd := range s.daemons {
			dlist = append(dlist, map[string]interface{}{
				"name": dd.name, "addr": dd.addr,
				"socks": dd.socks, "ready": dd.ready})
		}
		if s.d != nil {
			dName = s.d.name + " " + s.d.addr
		}
		s.dmu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"hunting": hunting, "last_mbps": last, "best_mbps": best,
			"last_at": lastAt, "best_at": bestAt,
			"hunt_best_mbps": huntBestMB, "hunt_best_name": huntBestName,
			"pinned_exit": pin, "pinned_name": pinName, "socks": socks,
			"exit_ip": exitIP, "exit_name": exitName,
			"proxy": proxyState(), "direct_mbps": direct,
			"daemon": dName, "daemons": dlist,
		})
	case "/api/daemon":
		addr := r.FormValue("addr")
		s.dmu.Lock()
		for _, dd := range s.daemons {
			if dd.addr == addr {
				s.d = dd
			}
		}
		active := ""
		if s.d != nil {
			active = s.d.name + " " + s.d.addr
		}
		s.dmu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"daemon": active})
	case "/api/compare":
		go s.compare()
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	case "/api/proxy":
		turnOn := !proxyState()
		if on := r.FormValue("on"); on != "" {
			turnOn = on == "1" || on == "true" || on == "on"
		}
		if turnOn {
			if d := s.daemon(); d != nil {
				if c, err := d.connect(); err == nil {
					socks, _ := socksAddr(c)
					c.close()
					if err := proxySetFn(true, socks); err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
				}
			}
		} else {
			proxySetFn(false, "")
		}
		json.NewEncoder(w).Encode(map[string]bool{"proxy": proxyState()})
	case "/api/hunt":
		s.startHunt()
	case "/api/stop":
		s.mu.Lock()
		if s.cancel != nil {
			s.cancel()
		}
		s.mu.Unlock()
	case "/api/abort":
		s.mu.Lock()
		if s.cancel != nil {
			s.cancel()
		}
		s.mu.Unlock()
		go func() {
			for i := 0; i < 60; i++ {
				s.mu.Lock()
				h := s.hunting
				s.mu.Unlock()
				if !h {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if d := s.daemon(); d != nil {
				if c, err := d.connect(); err == nil {
					unpin(c)
					c.cmd("SIGNAL NEWNYM")
					c.close()
					s.logf("aborted – random selection active.")
				}
			}
		}()
	case "/api/unpin":
		go func() {
			if d := s.daemon(); d != nil {
				if c, err := d.connect(); err == nil {
					unpin(c)
					c.cmd("SIGNAL NEWNYM")
					c.close()
					s.logf("pin removed – random selection active.")
				}
			}
		}()
	case "/api/measure":
		s.measure()
	case "/api/open":
		if err := openBrowser(); err != nil {
			s.logf("browser start: %v", err)
		} else {
			s.logf("browser launched with Tor.")
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	ch := s.hub.add()
	defer s.hub.drop(ch)
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			fl.Flush()
		}
	}
}

func (s *server) bwPump() {
	for {
		d := s.daemon()
		if d == nil {
			time.Sleep(3 * time.Second)
			continue
		}
		c, err := d.connect()
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		if _, err = c.cmd("SETEVENTS BW"); err != nil {
			c.close()
			time.Sleep(3 * time.Second)
			continue
		}
		for {
			l, err := c.readLine()
			if err != nil {
				c.close()
				break
			}
			var rd, wr int64
			if n, _ := fmt.Sscanf(l, "650 BW %d %d", &rd, &wr); n == 2 {
				s.hub.pub(fmt.Sprintf(`{"type":"bw","down":%d,"up":%d}`, rd, wr))
			}
		}
		time.Sleep(3 * time.Second)
	}
}

const dashHTML = `<!doctype html><meta charset=utf-8><title>torspeed</title>
<style>
body{background:#111;color:#eee;font:16px/1.5 system-ui;max-width:640px;margin:2em auto;padding:0 1em}
#speed{font-size:4em;font-weight:700}
#speed.hunt{color:#2b6}
@keyframes pop{0%{transform:scale(1)}30%{transform:scale(1.12)}100%{transform:scale(1)}}
#speed.pulse{animation:pop .4s}
#cap{color:#888;font-size:13px}
#lv,#eip{color:#777;font-size:12px}
#res,#stat{color:#bbb;font-size:14px;min-height:1.3em}
button{background:#2b6;padding:0.5em 1em;border:0;border-radius:6px;color:#fff;margin:.2em;cursor:pointer}
button.sec{background:#555}button:disabled{opacity:.4;cursor:default}
#log{white-space:pre-wrap;font:12px monospace;background:#000;padding:1em;border-radius:6px;max-height:14em;overflow:auto}
select{background:#222;color:#bbb;border:0;font-size:14px}
a{color:#6c8;cursor:pointer;margin-left:.5em;font-size:14px}
label{color:#bbb;font-size:14px}
</style>
<h1>torspeed</h1>
<div id=speed>– <small>Mbit/s</small></div>
<div id=cap>live traffic · Mbit/s</div>
<div id=lv style="display:none"></div>
<div id=eip></div>
<div id=res>–</div>
<div id=meta></div>
<div id=stat></div>
<div>Tor daemon: <select id=ds></select><a id=vs>Compare</a></div>
<label><input type=checkbox id=vc> System proxy → Tor</label><br>
<button id=h onclick=hunt()>Find fastest exit</button>
<button class=sec id=n onclick=unpin()>Unpin exit</button>
<button class=sec id=m onclick=post('measure')>Measure</button>
<button class=sec onclick=post('open')>Open Tor window</button>
<div id=log></div>
<script>
const log=m=>{const l=document.getElementById('log');l.textContent+=m+'\n';l.scrollTop=1e9};
const post=p=>fetch('/api/'+p,{method:'POST'});
let hunting=false,dkey='',live='–',huntBest={v:0,n:''},
 liveProbe={v:0,n:''},shownV=0,anim=0;
const speed=document.getElementById('speed'),cap=document.getElementById('cap'),
 lv=document.getElementById('lv');
// While a hunt runs, the big number behaves like a speedometer needle:
// a faster probe pushes it up instantly, then it glides back down to
// the true mean – the settled value is the one that gets pinned.
const truth=()=>Math.max(huntBest.v,liveProbe.v);
const truthName=()=>liveProbe.v>huntBest.v?liveProbe.n:huntBest.n;
const renderBig=()=>{
 if(!hunting){if(anim)cancelAnimationFrame(anim);anim=0;shownV=0;
  speed.classList.remove('hunt');
  speed.innerHTML=live+' <small>Mbit/s</small>';
  cap.textContent='live traffic · Mbit/s';lv.style.display='none';return;}
 speed.classList.add('hunt');
 speed.textContent=shownV?shownV.toFixed(1):'–';
 cap.textContent=shownV?'fastest so far · Mbit/s — '+truthName()
  :'searching…';
 lv.textContent='live traffic '+live+' Mbit/s';lv.style.display='';};
const settle=()=>{anim=0;
 const t=truth();
 if(Math.abs(shownV-t)<=0.05){shownV=t;renderBig();return;}
 shownV+=(t-shownV)*0.15;renderBig();
 anim=requestAnimationFrame(settle);};
const push=()=>{
 const t=truth();
 if(t>shownV+0.04){shownV=t;pulse();}
 renderBig();
 if(!anim)anim=requestAnimationFrame(settle);};
const hunt=()=>{post(hunting?'stop':'hunt');setTimeout(poll,500)};
const unpin=()=>{post(hunting?'abort':'unpin');setTimeout(poll,500)};
const fmtRes=s=>{
 const bestNewer=(s.best_at||0)>=(s.last_at||0);
 const v=bestNewer?s.best_mbps:s.last_mbps,t=bestNewer?s.best_at:s.last_at;
 const parts=[];
 if(v){let x='Tor '+v.toFixed(1);
  if(t)x+=' ('+Math.max(0,Math.round((Date.now()/1000-t)/60))+' min ago)';
  parts.push(x);}
 if(s.direct_mbps>0)parts.push('direct '+Math.round(s.direct_mbps)+' Mbit/s');
 return parts.length?parts.join(' · '):'–';};
const poll=()=>fetch('/api/status').then(r=>r.json()).then(s=>{
 hunting=!!s.hunting;
 huntBest={v:s.hunt_best_mbps||0,n:s.hunt_best_name||''};
 if(!hunting)liveProbe={v:0,n:''};
 renderBig();
 const h=document.getElementById('h'),n=document.getElementById('n');
 h.textContent=hunting?'Stop & keep best':'Find fastest exit';
 h.className=hunting?'sec':'';
 n.textContent=hunting?'Cancel (unpin)':'Unpin exit';
 document.getElementById('m').disabled=hunting;
 document.getElementById('res').textContent=fmtRes(s);
 let t=s.pinned_exit?'Pinned: '+(s.pinned_name||s.pinned_exit.slice(0,12)+'…')
  :'Random exit (not pinned)';
 document.getElementById('stat').textContent=(hunting?'Hunting… ':'')+t;
 const dl=s.daemons||[],ds=document.getElementById('ds'),
  key=dl.map(x=>x.addr+(x.ready?1:0)).join();
 if(key!==dkey){dkey=key;ds.innerHTML='';
  dl.forEach(x=>{const o=document.createElement('option');o.value=x.addr;
   o.textContent=x.name+(x.ready?'':' (not ready)');ds.appendChild(o)});}
 dl.forEach(x=>{if(s.daemon&&s.daemon.indexOf(x.addr)>=0)ds.value=x.addr});
 document.getElementById('vc').checked=!!s.proxy;
 document.getElementById('eip').textContent=s.exit_ip?'exit IP '+s.exit_ip+
  (s.exit_name?' ('+s.exit_name+')':''):'';
}).catch(()=>{document.getElementById('stat').textContent='offline';});
document.getElementById('ds').onchange=e=>
 post('daemon?addr='+encodeURIComponent(e.target.value));
document.getElementById('vs').onclick=()=>post('compare');
document.getElementById('vc').onchange=e=>
 fetch('/api/proxy?on='+(e.target.checked?1:0),{method:'POST'})
 .then(r=>r.json()).then(d=>{e.target.checked=d.proxy})
 .catch(()=>{e.target.checked=!e.target.checked});
const es=new EventSource('/events');
const bws=[];
const pulse=()=>{speed.classList.remove('pulse');void speed.offsetWidth;
 speed.classList.add('pulse');};
es.onmessage=e=>{const d=JSON.parse(e.data);
 if(d.type=='bw'){bws.push(d.down);if(bws.length>3)bws.shift();
  live=(bws.reduce((a,b)=>a+b,0)/bws.length*8/1e6).toFixed(1);
  renderBig();document.title='⬇ '+live+' Mbit/s';}
 if(d.type=='best'){huntBest={v:d.v,n:d.name};push();}
 if(d.type=='prog'){liveProbe={v:d.v,n:d.name};
  document.getElementById('meta').textContent='probe '+(d.name?d.name+': ':'')+d.v.toFixed(1)+' Mbit/s';
  push();}
 if(d.type=='log'){log(d.msg);poll();}
 if(d.type=='mbps'){log('→ '+d.v+' Mbit/s');poll();}};
poll();setInterval(poll,5000);
</script>`

func (s *server) run(port int) error {
	go s.bwPump()
	// Keep the system proxy pointed at a ready daemon's current port.
	go func() {
		for range time.Tick(30 * time.Second) {
			s.daemon()
			s.proxyCheck()
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, dashHTML)
			return
		}
		s.api(w, r)
	})
	mux.HandleFunc("/events", s.events)
	mux.HandleFunc("/api/", s.api)
	fmt.Printf("Dashboard: http://127.0.0.1:%d\n", port)
	fmt.Printf("Bookmarklet: javascript:fetch('http://127.0.0.1:%d/api/hunt',{method:'POST'})\n", port)
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: mux}
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		srv.Close() // hard close: SSE connections must not block shutdown
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// ---------- Extension ----------

// extID is the fixed extension ID derived from the key in
// extension/manifest.json – required so the nativeMessaging host manifest
// can name allowed_origins.
const extID = "dggpglknpcbfncdfphghhbobapcihhob"

// extensionFS embeds the browser extension sources so a single binary can
// install them anywhere (--install-ext). The files under extension/ are the
// single source of truth.
//
//go:embed extension/manifest.json extension/popup.html extension/popup.js extension/bg.js
var extensionFS embed.FS

// nmHostDirs returns the NativeMessagingHosts directories per OS; the
// manifest lets the extension start the binary when --serve is not running.
func nmHostDirs() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support",
			"BraveSoftware", "Brave-Browser", "NativeMessagingHosts"),
			filepath.Join(home, "Library", "Application Support",
				"Google", "Chrome", "NativeMessagingHosts")}
	case "windows":
		// On Windows the manifest path must go into the registry
		// (HKCU\Software\BraveSoftware\NativeMessagingHosts or Google\Chrome).
		return nil
	default:
		return []string{filepath.Join(home, ".config", "BraveSoftware",
			"Brave-Browser", "NativeMessagingHosts"),
			filepath.Join(home, ".config", "google-chrome",
				"NativeMessagingHosts")}
	}
}

func installNMHost() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	manifest := fmt.Sprintf(`{
 "name": "com.torspeed.host",
 "description": "torspeed native host",
 "path": %q,
 "type": "stdio",
 "allowed_origins": ["chrome-extension://%s/"]
}`, self, extID)
	var written []string
	for _, d := range nmHostDirs() {
		if err := os.MkdirAll(d, 0o755); err != nil {
			continue
		}
		p := filepath.Join(d, "com.torspeed.host.json")
		if err := os.WriteFile(p, []byte(manifest), 0o644); err == nil {
			written = append(written, p)
		}
	}
	if runtime.GOOS == "windows" {
		fmt.Println("  (Windows: NM host registry entries must be added manually)")
		return nil
	}
	if len(written) == 0 {
		return errors.New("no NativeMessagingHosts directory writable")
	}
	for _, p := range written {
		fmt.Println("  NM host:", p)
	}
	return nil
}

// nativeHost runs when a browser launches us as an NM host:
// read one message → make sure --serve is running → reply → exit.
func nativeHost() {
	readMsg := func() ([]byte, error) {
		var hdr [4]byte
		if _, err := io.ReadFull(os.Stdin, hdr[:]); err != nil {
			return nil, err
		}
		n := binary.LittleEndian.Uint32(hdr[:])
		if n > 1<<20 {
			return nil, errors.New("NM message too large")
		}
		buf := make([]byte, n)
		_, err := io.ReadFull(os.Stdin, buf)
		return buf, err
	}
	writeMsg := func(s string) {
		hdr := [4]byte{}
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(s)))
		os.Stdout.Write(hdr[:])
		os.Stdout.WriteString(s)
	}
	msg, err := readMsg()
	status := "running"
	if err == nil && strings.Contains(string(msg), "ensure") {
		if !serverAlive() {
			if self, e := os.Executable(); e == nil {
				devNull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
				cmd := exec.Command(self, "--serve")
				cmd.Stdin, cmd.Stdout, cmd.Stderr = devNull, devNull, devNull
				if err := cmd.Start(); err == nil {
					status = "started"
				}
			}
		}
	}
	writeMsg(fmt.Sprintf(`{"ok":true,"serve":%q}`, status))
}

func serverAlive() bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:8765", 400*time.Millisecond)
	if err == nil {
		c.Close()
		return true
	}
	return false
}

func installExt() error {
	dir := filepath.Join(os.Getenv("HOME"), "src", "torspeed", "extension")
	if runtime.GOOS == "windows" {
		dir = filepath.Join(os.Getenv("USERPROFILE"),
			"src", "torspeed", "extension")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ents, err := extensionFS.ReadDir("extension")
	if err != nil {
		return err
	}
	for _, e := range ents {
		data, err := extensionFS.ReadFile("extension/" + e.Name())
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			return err
		}
	}
	fmt.Println("extension written to:", dir)
	if err := installNMHost(); err != nil {
		fmt.Println("NM host:", err)
	}
	fmt.Println("\nInstallation (one time):")
	fmt.Println("  1. open brave://extensions")
	fmt.Println("  2. enable 'Developer mode' (top right)")
	fmt.Println("  3. 'Load unpacked' -> select the folder above")
	fmt.Println("  4. enable 'Allow in Incognito' (for Tor windows)")
	fmt.Println("  5. done – the extension starts --serve on demand")
	return nil
}

// ---------- main ----------

func fatal(err error) { fmt.Fprintln(os.Stderr, "Error:", err); os.Exit(1) }

func main() {
	// A browser launches us as NM host: argv[1] = chrome-extension://ID.
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "chrome-extension://") {
		nativeHost()
		return
	}
	flag.Parse()

	if *fVer {
		fmt.Println("torspeed", version)
		return
	}
	if *fInstX {
		if err := installExt(); err != nil {
			fatal(err)
		}
		return
	}
	if *fOpen {
		if err := openBrowser(); err != nil {
			fatal(err)
		}
		return
	}
	if *fStartT {
		if err := spawnTor(); err != nil {
			fatal(err)
		}
		fmt.Println("tor daemon started (SOCKS 127.0.0.1:9050, control 127.0.0.1:9051)")
		return
	}
	if *fCompare {
		ds := discoverAll()
		if len(ds) == 0 {
			fatal(errors.New("no Tor daemon found"))
		}
		fmt.Printf("%d daemons found – measuring sequentially …\n", len(ds))
		best, bm := compareDaemons(ds, *fURL,
			func(f string, a ...interface{}) { fmt.Printf("  "+f+"\n", a...) })
		if best != nil {
			fmt.Printf("winner: %s (%.1f Mbit/s)\n", best.name, bm)
		}
		return
	}
	if *fProxy || *fNoProxy {
		if *fProxy {
			d, err := discover()
			if d == nil || err != nil {
				if e := spawnTor(); e == nil {
					fatal(e)
				}
				time.Sleep(2 * time.Second)
				d, _ = discover()
			}
			if d == nil {
				fatal(errors.New("no Tor daemon"))
			}
			c, err := d.connect()
			if err != nil {
				fatal(err)
			}
			socks, _ := socksAddr(c)
			c.close()
			if err := proxySet(true, socks); err != nil {
				fatal(err)
			}
			fmt.Println("system proxy ON: SOCKS", socks, "(proxy-aware apps through Tor)")
		} else {
			if err := proxySet(false, ""); err != nil {
				fatal(err)
			}
			fmt.Println("system proxy OFF.")
		}
		return
	}

	// --serve also starts without a running daemon; everything else needs one.
	d, err := discover()
	if *fServe {
		if d != nil {
			fmt.Println("tor daemon:", d.addr)
		} else {
			// No daemon → try spawning our own tor (if installed).
			if e := spawnTor(); e == nil {
				fmt.Println("spawned own tor daemon (127.0.0.1:9051)")
			} else {
				fmt.Println("no Tor daemon active – server will wait for one.")
			}
		}
		s := &server{d: d, daemons: discoverAll(), discover: discoverAll,
			hub: &hub{clients: map[chan string]bool{}},
			url: *fURL, target: *fTarget, candidates: *fCands, maxMB: *fMaxMB,
			samples: *fSamples}
		fatal(s.run(*fPort))
	}
	if err != nil {
		fatal(err)
	}
	fmt.Println("tor daemon:", d.addr)

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch {
	case *fWatch:
		watch(d, ctx)
	case *fUnpin:
		c, err := d.connect()
		if err != nil {
			fatal(err)
		}
		unpin(c)
		c.cmd("SIGNAL NEWNYM")
		fmt.Println("pin removed – random selection active.")
		c.close()
	case *fExit != "":
		c, err := d.connect()
		if err != nil {
			fatal(err)
		}
		defer c.close()
		lines, _ := c.getinfo("ns/all")
		var hit *relay
		for _, r := range parseConsensus(lines) {
			if strings.EqualFold(r.fp, *fExit) ||
				strings.Contains(strings.ToLower(r.name), strings.ToLower(*fExit)) {
				cp := r
				hit = &cp
				break
			}
		}
		if hit == nil {
			fatal(fmt.Errorf("relay '%s' not found", *fExit))
		}
		pin(c, hit.fp)
		closed := closeStaleCircuits(c, hit.fp)
		fmt.Printf("%d old circuits closed – tabs switch automatically\n", closed)
		c.cmd("SIGNAL NEWNYM")
		time.Sleep(4 * time.Second)
		socks, _ := socksAddr(c)
		res, err := speedTest(ctx, probeOpts{
			socks: socks, urls: testURLList(*fURL), maxMB: *fMaxMB, streams: 3,
			prog: func(_ string, v float64) {
				fmt.Printf("\r  measuring: %6.1f Mbit/s  ", v)
			}})
		fmt.Printf("\npinned: %s\n", hit.name)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%.1f Mbit/s\n", res.mbps)
	case *fCirc:
		c, err := d.connect()
		if err != nil {
			fatal(err)
		}
		showCircuits(c)
		c.close()
	case *fHunt:
		_, _, _ = hunt(ctx, d, *fTarget, *fCands, *fURL, *fMaxMB, *fSamples,
			func(m string) { fmt.Println(m) },
			func(name string, v float64) {
				fmt.Printf("\r  measuring %s: %6.1f Mbit/s          ", name, v)
			}, nil)
	default:
		c, err := d.connect()
		if err != nil {
			fatal(err)
		}
		socks, _ := socksAddr(c)
		res, err := speedTest(ctx, probeOpts{
			socks: socks, urls: testURLList(*fURL), maxMB: *fMaxMB, streams: 3,
			prog: func(_ string, v float64) {
				fmt.Printf("\r  measuring: %6.1f Mbit/s  ", v)
			}})
		c.close()
		if err != nil {
			fatal(err)
		}
		fmt.Printf("\n%.1f Mbit/s\n", res.mbps)
	}
}
