package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- helpers ----------

// fakeCtrl wires a *ctrl to a scripted in-memory control server via net.Pipe.
// respond receives each command line and returns the reply lines to write
// (without CRLF). It may record commands for later assertions.
func fakeCtrl(t *testing.T, respond func(cmd string) []string) *ctrl {
	t.Helper()
	cli, srv := net.Pipe()
	c := &ctrl{conn: cli, r: bufio.NewReader(cli)}
	t.Cleanup(func() { c.close() })
	go func() {
		defer srv.Close()
		r := bufio.NewReader(srv)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			for _, out := range respond(strings.TrimRight(l, "\r\n")) {
				if _, err := srv.Write([]byte(out + "\r\n")); err != nil {
					return
				}
			}
		}
	}()
	return c
}

// socksRec collects what the fake SOCKS server observed (mutex-guarded).
type socksRec struct {
	mu   sync.Mutex
	user string
}

func (r *socksRec) username() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.user
}

// fakeSocks runs a minimal SOCKS5 server on a real loopback listener.
// rep is the reply code for CONNECT requests (0 = success, then echo).
// Supports method 0x00 and method 0x02 (RFC 1929); when the client
// authenticates, the username is stored in rec (may be nil).
func fakeSocks(t *testing.T, rep byte) string {
	t.Helper()
	return fakeSocksRec(t, rep, nil)
}

func fakeSocksRec(t *testing.T, rep byte, rec *socksRec) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head := make([]byte, 2)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				method := byte(0)
				if bytes.IndexByte(methods, 2) >= 0 {
					method = 2
				}
				if _, err := c.Write([]byte{5, method}); err != nil {
					return
				}
				if method == 2 {
					// RFC 1929: VER ULEN UNAME PLEN PASSWD
					b := make([]byte, 2)
					if _, err := io.ReadFull(c, b); err != nil || b[0] != 1 {
						return
					}
					u := make([]byte, int(b[1]))
					if _, err := io.ReadFull(c, u); err != nil {
						return
					}
					if _, err := io.ReadFull(c, b[:1]); err != nil {
						return
					}
					if _, err := io.ReadFull(c,
						make([]byte, int(b[0]))); err != nil {
						return
					}
					if rec != nil {
						rec.mu.Lock()
						rec.user = string(u)
						rec.mu.Unlock()
					}
					if _, err := c.Write([]byte{1, 0}); err != nil {
						return
					}
				}
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				switch hdr[3] {
				case 1:
					io.ReadFull(c, make([]byte, 4))
				case 3:
					lb := make([]byte, 1)
					io.ReadFull(c, lb)
					io.ReadFull(c, make([]byte, int(lb[0])))
				case 4:
					io.ReadFull(c, make([]byte, 16))
				}
				io.ReadFull(c, make([]byte, 2)) // port
				if rep != 0 {
					c.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				io.Copy(c, c) // echo
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// b64fp returns a consensus-style base64 identity fingerprint whose decoded
// hex form is predictable (20 copies of b).
func b64fp(b byte) string {
	return base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 20))
}

// ---------- control client ----------

func TestIsDigits(t *testing.T) {
	for s, want := range map[string]bool{"123": true, "1a2": false, "": false} {
		if got := isDigits(s); got != want {
			t.Errorf("isDigits(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestCtrlCmdReply(t *testing.T) {
	c := fakeCtrl(t, func(cmd string) []string {
		if cmd == "GETINFO version" {
			return []string{"250-version=0.4.8.12", "250 OK"}
		}
		return []string{"510 Unrecognized command"}
	})
	lines, err := c.cmd("GETINFO version")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "250-version=0.4.8.12" || lines[1] != "250 OK" {
		t.Fatalf("unexpected reply: %v", lines)
	}
}

func TestGetinfoSingleAndBlock(t *testing.T) {
	c := fakeCtrl(t, func(cmd string) []string {
		switch cmd {
		case "GETINFO version":
			return []string{"250-version=0.4.8.12", "250 OK"}
		case "GETINFO ns/all":
			return []string{"250+ns/all=", "r Foo abc", "r Bar def", ".", "250 OK"}
		}
		return []string{"250 OK"}
	})
	v, err := c.getinfo("version")
	if err != nil || len(v) != 1 || v[0] != "0.4.8.12" {
		t.Fatalf("version: %v err=%v", v, err)
	}
	ns, err := c.getinfo("ns/all")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0] != "r Foo abc" || ns[1] != "r Bar def" {
		t.Fatalf("ns/all: %v", ns)
	}
}

func TestPinUnpinCommands(t *testing.T) {
	var got []string
	c := fakeCtrl(t, func(cmd string) []string {
		got = append(got, cmd)
		return []string{"250 OK"}
	})
	pin(c, "DEADBEEF")
	unpin(c)
	// StrictNodes must not be touched: it does not apply to ExitNodes and
	// would clobber the user's ExcludeNodes strictness.
	want := []string{
		"SETCONF ExitNodes=$DEADBEEF", "RESETCONF ExitNodes",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands = %v, want %v", got, want)
	}
}

func TestPinnedExit(t *testing.T) {
	c := fakeCtrl(t, func(cmd string) []string {
		if cmd == "GETCONF ExitNodes" {
			return []string{"250-ExitNodes=$DEADBEEF", "250 OK"}
		}
		return []string{"250 OK"}
	})
	if p := pinnedExit(c); p != "DEADBEEF" {
		t.Fatalf("pinnedExit = %q", p)
	}
}

func TestPinnedExitEmpty(t *testing.T) {
	c := fakeCtrl(t, func(cmd string) []string {
		if cmd == "GETCONF ExitNodes" {
			return []string{"250-ExitNodes", "250 OK"}
		}
		return []string{"250 OK"}
	})
	if p := pinnedExit(c); p != "" {
		t.Fatalf("pinnedExit = %q, want empty", p)
	}
}

func TestAuthSafe(t *testing.T) {
	cookie := bytes.Repeat([]byte{0xAA}, 32)
	snonce := bytes.Repeat([]byte{0x42}, 32)
	var clientNonce []byte
	c := fakeCtrl(t, func(cmd string) []string {
		switch {
		case strings.HasPrefix(cmd, "AUTHCHALLENGE SAFECOOKIE "):
			clientNonce, _ = hex.DecodeString(
				strings.TrimPrefix(cmd, "AUTHCHALLENGE SAFECOOKIE "))
			// Real reply is a single line per control-spec:
			// "250 AUTHCHALLENGE SERVERHASH=x SERVERNONCE=y"
			return []string{
				"250 AUTHCHALLENGE SERVERHASH=" + strings.Repeat("00", 32) +
					" SERVERNONCE=" + hex.EncodeToString(snonce)}
		case strings.HasPrefix(cmd, "AUTHENTICATE "):
			h := hmac.New(sha256.New, []byte(
				"Tor safe cookie authentication controller-to-server hash"))
			h.Write(append(append(append([]byte{}, cookie...),
				clientNonce...), snonce...))
			if cmd == "AUTHENTICATE "+hex.EncodeToString(h.Sum(nil)) {
				return []string{"250 OK"}
			}
			return []string{"515 Authentication failed"}
		}
		return []string{"250 OK"}
	})
	d := &daemon{addr: "x"}
	if err := d.authSafe(c, cookie); err != nil {
		t.Fatalf("authSafe: %v", err)
	}
}

// ---------- consensus ----------

func TestParseConsensus(t *testing.T) {
	lines := []string{
		"r FastExit " + b64fp(0x11) + " dGVzdA 2025-01-01 12:00:00 1.2.3.4 443 0",
		"s Exit Fast Running Stable Valid",
		"w Bandwidth=50000",
		"p accept 80,443",
		"r NoExit " + b64fp(0x22) + " dGVzdA 2025-01-01 12:00:00 5.6.7.8 9001 0",
		"s Fast Running Stable Valid",
		"w Bandwidth=90000",
		"r BadExit " + b64fp(0x66) + " dGVzdA 2025-01-01 12:00:00 3.3.3.3 443 0",
		"s Exit BadExit Running Valid",
		"w Bandwidth=70000",
		"p accept 80,443",
	}
	rs := parseConsensus(lines)
	if len(rs) != 3 {
		t.Fatalf("relays = %d, want 3", len(rs))
	}
	wantFP := strings.ToUpper(hex.EncodeToString(bytes.Repeat([]byte{0x11}, 20)))
	if rs[0].name != "FastExit" || rs[0].fp != wantFP {
		t.Fatalf("relay 0: %+v", rs[0])
	}
	if !rs[0].exit || !rs[0].running || rs[0].bw != 50000 || rs[0].pol != "accept 80,443" {
		t.Fatalf("relay 0 fields: %+v", rs[0])
	}
	if rs[1].exit || rs[1].pol != "" {
		t.Fatalf("relay 1 fields: %+v", rs[1])
	}
	if rs[2].exit {
		t.Fatal("BadExit flag must clear exit")
	}
}

func TestCoversPort(t *testing.T) {
	cases := []struct {
		pol  string
		port int
		want bool
	}{
		{"accept 80,443", 443, true},
		{"accept 80,443", 80, true},
		{"accept 20-23,53", 80, false},
		{"accept 6660-6699", 6667, true},
		{"reject 1-65535", 80, false},
		{"reject 1-1024", 8080, true}, // port outside the reject range
		{"accept *:*", 443, true},
		{"reject *:*", 443, false},
		{"accept *", 22, true},
		{"bogus", 80, false},
	}
	for _, tc := range cases {
		if got := coversPort(tc.pol, tc.port); got != tc.want {
			t.Errorf("coversPort(%q, %d) = %v, want %v", tc.pol, tc.port, got, tc.want)
		}
	}
}

func fpHex(b byte) string {
	return strings.ToUpper(hex.EncodeToString(bytes.Repeat([]byte{b}, 20)))
}

func TestTopExits(t *testing.T) {
	ns := []string{
		"r FastExit " + b64fp(0x11) + " dGVzdA 2025-01-01 12:00:00 1.2.3.4 443 0",
		"s Exit Fast Running Valid",
		"w Bandwidth=50000",
		"p accept 80,443",
		"r NoExit " + b64fp(0x22) + " dGVzdA 2025-01-01 12:00:00 5.6.7.8 9001 0",
		"s Fast Running Valid",
		"w Bandwidth=90000",
		"r MidExit " + b64fp(0x33) + " dGVzdA 2025-01-01 12:00:00 9.9.9.9 443 0",
		"s Exit Running Valid",
		"w Bandwidth=30000",
		"r LazyExit " + b64fp(0x44) + " dGVzdA 2025-01-01 12:00:00 8.8.8.8 443 0",
		"s Exit Running Valid",
		"w Bandwidth=40000",
		"r DownExit " + b64fp(0x55) + " dGVzdA 2025-01-01 12:00:00 7.7.7.7 443 0",
		"s Exit Valid",
		"w Bandwidth=99999",
		"p accept 80,443",
		"r BadExit " + b64fp(0x66) + " dGVzdA 2025-01-01 12:00:00 3.3.3.3 443 0",
		"s Exit BadExit Running Valid",
		"w Bandwidth=88888",
		"p accept 80,443",
		"r NoMD " + b64fp(0x77) + " dGVzdA 2025-01-01 12:00:00 2.2.2.2 443 0",
		"s Exit Running Valid",
		"w Bandwidth=20000",
		"r WebOnly " + b64fp(0x88) + " dGVzdA 2025-01-01 12:00:00 6.6.6.6 443 0",
		"s Exit Running Valid",
		"w Bandwidth=10000",
		"p accept 80",
	}
	c := fakeCtrl(t, func(cmd string) []string {
		if cmd == "GETINFO ns/all" {
			out := append([]string{"250+ns/all="}, ns...)
			return append(out, ".", "250 OK")
		}
		if fp := strings.TrimPrefix(cmd, "GETINFO md/id/"); fp != cmd {
			switch fp {
			case fpHex(0x33): // MidExit: microdescriptor rejects web ports
				return []string{"250+md/id/" + fp + "=",
					"onion-key", "p reject 1-65535", ".", "250 OK"}
			case fpHex(0x44): // LazyExit: microdescriptor allows them
				return []string{"250+md/id/" + fp + "=",
					"onion-key", "p accept 80,443", ".", "250 OK"}
			default: // e.g. NoMD: unknown → keep the relay
				return []string{"552 Unrecognized key"}
			}
		}
		return []string{"250 OK"}
	})
	got, err := topExits(c, 60)
	if err != nil {
		t.Fatal(err)
	}
	// Kept: FastExit (p accept 80,443), LazyExit (md allows 80+443),
	// NoMD (md lookup failed → kept). Dropped: NoExit (no Exit flag),
	// DownExit (not Running), BadExit (BadExit flag), MidExit (md rejects
	// all ports), WebOnly (p covers 80 but not 443).
	var names []string
	for _, r := range got {
		names = append(names, r.name)
	}
	want := []string{"FastExit", "LazyExit", "NoMD"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("topExits = %v, want %v", names, want)
	}
	if one, _ := topExits(c, 1); len(one) != 1 || one[0].name != "FastExit" {
		t.Fatalf("topExits n=1 = %+v", one)
	}
}

// ---------- hunt helpers ----------

func TestBar(t *testing.T) {
	if got := bar(10, 25, 12); got != "[####--------]" {
		t.Fatalf("bar = %q", got)
	}
	if got := bar(30, 25, 12); got != "[############]" {
		t.Fatalf("bar clamp = %q", got)
	}
	if got := bar(0, 0, 4); got != "[----]" {
		t.Fatalf("bar empty = %q", got)
	}
}

func TestSleepCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	sleepCtx(ctx, time.Hour)
	if time.Since(start) > time.Second {
		t.Fatal("sleepCtx ignored canceled ctx")
	}
	start = time.Now()
	sleepCtx(context.Background(), 10*time.Millisecond)
	if time.Since(start) < 10*time.Millisecond {
		t.Fatal("sleepCtx returned early")
	}
}

// ---------- SOCKS5 ----------

func TestDialSocksDomain(t *testing.T) {
	addr := fakeSocks(t, 0)
	conn, err := dialSocks(context.Background(), addr, "", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q err=%v", buf, err)
	}
}

func TestDialSocksIPv4(t *testing.T) {
	addr := fakeSocks(t, 0)
	conn, err := dialSocks(context.Background(), addr, "", "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialSocksRefused(t *testing.T) {
	addr := fakeSocks(t, 0x05)
	_, err := dialSocks(context.Background(), addr, "", "example.com:80")
	if err == nil || !strings.Contains(err.Error(), "0x05") {
		t.Fatalf("err = %v, want SOCKS connect error 0x05", err)
	}
}

func TestDialSocksUserAuth(t *testing.T) {
	rec := &socksRec{}
	addr := fakeSocksRec(t, 0, rec)
	conn, err := dialSocks(context.Background(), addr,
		"hunt-abc123", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if u := rec.username(); u != "hunt-abc123" {
		t.Fatalf("username = %q, want %q", u, "hunt-abc123")
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q err=%v", buf, err)
	}
}

// ---------- speed test ----------

func TestSpeedTestDirect(t *testing.T) {
	old := testURLs
	testURLs = nil // never hit the real fallback URLs in tests
	defer func() { testURLs = old }()

	var served int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := w.Write(bytes.Repeat([]byte{'x'}, 2<<20)) // 2 MiB per request
		atomic.AddInt64(&served, int64(n))
	}))
	defer srv.Close()

	res, err := speedTest(context.Background(), probeOpts{
		urls: []string{srv.URL + "/f"}, maxMB: 8, streams: 3})
	if err != nil {
		t.Fatal(err)
	}
	if res.mbps <= 0 {
		t.Fatalf("rate = %v, want > 0", res.mbps)
	}
	if res.url != srv.URL+"/f" || res.bytes < 6e6 {
		t.Fatalf("url = %q bytes = %d", res.url, res.bytes)
	}
	if got := atomic.LoadInt64(&served); got < 6e6 {
		t.Fatalf("served = %d bytes, want >= 6e6", got)
	}
}

func TestSpeedTestAllURLsFail(t *testing.T) {
	old := testURLs
	testURLs = nil
	defer func() { testURLs = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := srv.URL
	srv.Close() // refuse connections

	_, err := speedTest(context.Background(), probeOpts{
		urls: []string{dead + "/f"}, maxMB: 1, streams: 1})
	if err == nil || !strings.Contains(err.Error(), "all test URLs failed") {
		t.Fatalf("err = %v", err)
	}
}

func TestSpeedTestNon2xxFails(t *testing.T) {
	old := testURLs
	testURLs = nil
	defer func() { testURLs = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("no way"))
	}))
	defer srv.Close()

	_, err := speedTest(context.Background(), probeOpts{
		urls: []string{srv.URL + "/f"}, maxMB: 1, streams: 1})
	if err == nil || !strings.Contains(err.Error(), "all test URLs failed") {
		t.Fatalf("err = %v", err)
	}
}

// TestSpeedTestTTFBExcluded: setup time must not drag the rate down –
// mbps is measured only over the steady-state transfer.
func TestSpeedTestTTFBExcluded(t *testing.T) {
	old := testURLs
	testURLs = nil
	defer func() { testURLs = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(800 * time.Millisecond) // slow TTFB
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		w.Write(bytes.Repeat([]byte{'x'}, 4<<20)) // ~4 MB body
	}))
	defer srv.Close()

	start := time.Now()
	res, err := speedTest(context.Background(), probeOpts{
		urls: []string{srv.URL + "/f"}, maxMB: 8, streams: 2})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if res.ttfb < 700*time.Millisecond {
		t.Fatalf("ttfb = %v, want >= 700ms", res.ttfb)
	}
	naive := float64(res.bytes) * 8 / elapsed.Seconds() / 1e6
	if res.mbps <= naive {
		t.Fatalf("mbps = %.1f, want > naive %.1f (setup excluded)",
			res.mbps, naive)
	}
}

// TestSpeedTestReRequest: small bodies must saturate anyway – EOF with
// budget left triggers another request on the same URL.
func TestSpeedTestReRequest(t *testing.T) {
	old := testURLs
	testURLs = nil
	defer func() { testURLs = old }()

	var reqs int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqs, 1)
		w.Write(bytes.Repeat([]byte{'x'}, 512<<10)) // 512 KiB each
	}))
	defer srv.Close()

	res, err := speedTest(context.Background(), probeOpts{
		urls: []string{srv.URL + "/f"}, maxMB: 3, streams: 2})
	if err != nil {
		t.Fatal(err)
	}
	// 3e6 bytes need at least 6 bodies of 512 KiB. Counted client-side:
	// server-side Write counts under-report when the client hangs up.
	if res.bytes < 3e6 {
		t.Fatalf("received = %d bytes, want >= 3e6 (re-requests)", res.bytes)
	}
	if got := atomic.LoadInt64(&reqs); got < 6 {
		t.Fatalf("requests = %d, want >= 6", got)
	}
}

// TestSpeedTestMaxDur: the transfer phase ends at t0+maxDur even when the
// body never finishes and ctx is context.Background().
func TestSpeedTestMaxDur(t *testing.T) {
	old := testURLs
	testURLs = nil
	defer func() { testURLs = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte{'x'}, 64<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	start := time.Now()
	res, err := speedTest(context.Background(), probeOpts{
		urls: []string{srv.URL + "/f"}, maxMB: 1000, maxDur: time.Second,
		streams: 1})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v, want < 3s (maxDur 1s)", d)
	}
	if res.bytes == 0 {
		t.Fatal("no bytes received")
	}
}

// TestSpeedTestProgStops: the sampler is joined before return – prog may
// never fire afterwards and no goroutine may leak.
func TestSpeedTestProgStops(t *testing.T) {
	old := testURLs
	testURLs = nil
	defer func() { testURLs = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte{'x'}, 2<<20))
	}))
	defer srv.Close()

	var returned, late int32
	_, err := speedTest(context.Background(), probeOpts{
		urls: []string{srv.URL + "/f"}, maxMB: 1, streams: 1,
		prog: func(string, float64) {
			if atomic.LoadInt32(&returned) == 1 {
				atomic.AddInt32(&late, 1)
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	atomic.StoreInt32(&returned, 1)
	time.Sleep(1500 * time.Millisecond)
	if n := atomic.LoadInt32(&late); n != 0 {
		t.Fatalf("prog called %d times after return", n)
	}
}

// ---------- server / API ----------

func newTestServer() *server {
	return &server{
		hub:        &hub{clients: map[chan string]bool{}},
		discover:   func() []*daemon { return nil },
		url:        "http://127.0.0.1/f",
		candidates: 4, maxMB: 1, samples: 1,
		directAt: time.Now(), // suppress ensureDirect's real network probe
	}
}

func TestAPIStatus(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"hunting", "last_mbps", "best_mbps", "pinned_exit",
		"pinned_name", "socks", "proxy", "direct_mbps", "daemon", "daemons",
		"last_at", "best_at", "hunt_best_mbps", "hunt_best_name",
		"exit_ip", "exit_name"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %v", k, m)
		}
	}
}

func TestAPIOptions(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodOptions, "/api/status", nil))
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS header")
	}
}

func TestAPINotFound(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodGet, "/api/bogus", nil))
	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAPIDaemonEmpty(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodPost,
		"/api/daemon?addr=127.0.0.1:9999", nil))
	var m map[string]string
	json.Unmarshal(rec.Body.Bytes(), &m)
	if m["daemon"] != "" {
		t.Fatalf("daemon = %q, want empty", m["daemon"])
	}
}

func TestAPIMeasureBusyDuringHunt(t *testing.T) {
	s := newTestServer()
	s.mu.Lock()
	s.hunting = true
	s.mu.Unlock()
	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodPost, "/api/measure", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	s.mu.Lock()
	measuring := s.measuring
	s.mu.Unlock()
	if measuring {
		t.Fatal("measuring = true while a hunt is running")
	}
}

// TestAPIStatusDaemonFields: daemons entries must carry socks/ready.
func TestAPIStatusDaemonFields(t *testing.T) {
	s := newTestServer()
	s.discover = func() []*daemon {
		return []*daemon{{name: "FakeD", addr: "127.0.0.1:9"}}
	}
	old := proxyStateProbe
	proxyStateProbe = func() bool { return false }
	defer func() { proxyStateProbe = old; proxyStateInvalidate() }()

	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	dl, _ := m["daemons"].([]interface{})
	if len(dl) != 1 {
		t.Fatalf("daemons = %v, want 1 entry", m["daemons"])
	}
	d := dl[0].(map[string]interface{})
	for _, k := range []string{"name", "addr", "socks", "ready"} {
		if _, ok := d[k]; !ok {
			t.Errorf("daemon entry missing %q: %v", k, d)
		}
	}
	if _, ok := m["proxy"]; !ok {
		t.Error("status missing proxy key")
	}
	if _, ok := m["last_at"]; !ok {
		t.Error("status missing last_at key")
	}
	if _, ok := m["best_at"]; !ok {
		t.Error("status missing best_at key")
	}
}

// TestAPICompareAndProxyRoutes: the renamed routes are wired; the system
// proxy must never really be toggled – proxySetFn is stubbed.
func TestAPICompareAndProxyRoutes(t *testing.T) {
	s := newTestServer()
	oldP, oldS := proxyStateProbe, proxySetFn
	proxyStateProbe = func() bool { return false }
	var calls []bool
	proxySetFn = func(on bool, _ string) error {
		calls = append(calls, on)
		return nil
	}
	defer func() {
		proxyStateProbe, proxySetFn = oldP, oldS
		proxyStateInvalidate()
	}()

	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodPost, "/api/compare", nil))
	if rec.Code != 200 {
		t.Fatalf("/api/compare = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodPost, "/api/proxy?on=0", nil))
	if rec.Code != 200 {
		t.Fatalf("/api/proxy = %d", rec.Code)
	}
	var m map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["proxy"]; !ok {
		t.Fatalf("reply missing proxy key: %v", m)
	}
	if len(calls) != 1 || calls[0] {
		t.Fatalf("proxySetFn calls = %v, want [false]", calls)
	}
}

// TestAPIOldRoutesGone: the pre-rename routes must not exist.
func TestAPIOldRoutesGone(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/api/vpn", "/api/versus"} {
		rec := httptest.NewRecorder()
		s.api(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != 404 {
			t.Fatalf("%s = %d, want 404", p, rec.Code)
		}
	}
}

func TestFlagRenames(t *testing.T) {
	for _, n := range []string{"target", "candidates", "proxy", "noproxy",
		"compare"} {
		if flag.Lookup(n) == nil {
			t.Errorf("flag --%s missing", n)
		}
	}
	for _, n := range []string{"min", "tries", "vpn", "novpn", "duel"} {
		if flag.Lookup(n) != nil {
			t.Errorf("stale flag --%s still registered", n)
		}
	}
}

// TestProxyStateCache: two proxyState calls within the TTL hit the OS
// probe only once.
func TestProxyStateCache(t *testing.T) {
	old := proxyStateProbe
	defer func() { proxyStateProbe = old; proxyStateInvalidate() }()
	var calls int32
	proxyStateProbe = func() bool {
		atomic.AddInt32(&calls, 1)
		return true
	}
	proxyStateInvalidate()
	if !proxyState() {
		t.Fatal("proxyState should return stubbed true")
	}
	if !proxyState() {
		t.Fatal("proxyState should return stubbed true (cached)")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("probe called %d times for 2 calls, want 1", n)
	}
}

// TestProxyCheck: a stale system-proxy port is re-pointed at a ready
// daemon (active first, else first ready); a fresh port means no call.
// TestOnHuntBest: the hunt's onBest callback updates the status keys and
// publishes a "best" SSE event for the gamified display.
func TestOnHuntBest(t *testing.T) {
	s := newTestServer()
	ch := s.hub.add()
	defer s.hub.drop(ch)
	s.onHuntBest("fastExit", 11.4)
	select {
	case msg := <-ch:
		if !strings.Contains(msg, `"type":"best"`) ||
			!strings.Contains(msg, `"name":"fastExit"`) ||
			!strings.Contains(msg, `"v":11.4`) {
			t.Fatalf("unexpected event %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no best event published")
	}
	rec := httptest.NewRecorder()
	s.api(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["hunt_best_mbps"] != 11.4 || m["hunt_best_name"] != "fastExit" {
		t.Fatalf("hunt best keys = %v / %v",
			m["hunt_best_mbps"], m["hunt_best_name"])
	}
}

// TestCloseStaleCircuits: only BUILT GENERAL/CONFLUX_LINKED circuits on a
// different exit are closed; the pinned exit's circuits, hidden-service
// and still-extending circuits are kept.
func TestCloseStaleCircuits(t *testing.T) {
	var mu sync.Mutex
	var cmds []string
	other := "$EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE~other"
	keep := "$keepfp0000000000000000000000000000000000~keep"
	a := "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~a"
	c := fakeCtrl(t, func(cmd string) []string {
		mu.Lock()
		cmds = append(cmds, cmd)
		mu.Unlock()
		if strings.HasPrefix(cmd, "GETINFO") {
			return []string{
				"250+circuit-status=",
				"1 BUILT " + a + "," + other + " PURPOSE=GENERAL",
				"2 BUILT " + a + "," + keep + " PURPOSE=GENERAL",
				"3 BUILT " + a + "," + other + " PURPOSE=HS_CLIENT_REND",
				"4 EXTENDED " + a + "," + other + " PURPOSE=GENERAL",
				"5 BUILT " + a + "," + other + " PURPOSE=CONFLUX_LINKED",
				".",
				"250 OK",
			}
		}
		return []string{"250 OK"}
	})
	n := closeStaleCircuits(c,
		"KEEPFP0000000000000000000000000000000000")
	if n != 2 {
		t.Fatalf("closed = %d, want 2", n)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"GETINFO circuit-status",
		"CLOSECIRCUIT 1", "CLOSECIRCUIT 5"}
	if len(cmds) != len(want) {
		t.Fatalf("cmds = %v, want %v", cmds, want)
	}
	for i := range want {
		if cmds[i] != want[i] {
			t.Fatalf("cmds = %v, want %v", cmds, want)
		}
	}
}

// TestExitInfo: unpinned → the newest BUILT general circuit's exit;
// pinned → the pin wins regardless of circuits. relayInfo parses the
// r line (name at index 1, OR IP at index 6).
func TestExitInfo(t *testing.T) {
	a := "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~a"
	o1 := "$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~oldExit"
	o2 := "$CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC~newExit"
	c := fakeCtrl(t, func(cmd string) []string {
		switch cmd {
		case "GETCONF ExitNodes":
			return []string{"250 OK"}
		case "GETINFO circuit-status":
			return []string{
				"250+circuit-status=",
				"1 BUILT " + a + "," + o1 + " PURPOSE=GENERAL",
				"2 BUILT " + a + "," + o1 + " PURPOSE=HS_CLIENT_REND",
				"3 EXTENDED " + a + " PURPOSE=GENERAL",
				"4 BUILT " + a + "," + o2 + " PURPOSE=GENERAL",
				".",
				"250 OK",
			}
		case "GETINFO ns/id/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC":
			return []string{
				"250+ns/id/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
				"r newExit QmFzZTY0aWQ zGlnZXN0 2026-10-21 20:00:00 171.5.4.3 443 0",
				".",
				"250 OK",
			}
		}
		return []string{"250 OK"}
	})
	if fp := lastCircuitExit(c); fp !=
		"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" {
		t.Fatalf("lastCircuitExit = %q", fp)
	}
	name, ip := relayInfo(c, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	if name != "newExit" || ip != "171.5.4.3" {
		t.Fatalf("relayInfo = %q %q", name, ip)
	}
}

func TestProxyCheck(t *testing.T) {
	oldP, oldPort, oldSet := proxyStateProbe, proxyPortProbe, proxySetFn
	t.Cleanup(func() {
		proxyStateProbe, proxyPortProbe, proxySetFn = oldP, oldPort, oldSet
		proxyStateInvalidate()
	})
	proxyStateProbe = func() bool { return true }
	proxyStateInvalidate()
	proxyPortProbe = func() string { return "60431" }

	brave := &daemon{name: "Brave-Tor", addr: "127.0.0.1:60432",
		socks: "127.0.0.1:60431", ready: false}
	system := &daemon{name: "System-Tor", addr: "127.0.0.1:9051",
		socks: "127.0.0.1:9050", ready: true}
	var calls []string
	proxySetFn = func(_ bool, socks string) error {
		calls = append(calls, socks)
		return nil
	}

	s := newTestServer()
	s.daemons = []*daemon{brave, system}
	s.d = brave
	s.proxyCheck()
	if len(calls) != 1 || calls[0] != "127.0.0.1:9050" {
		t.Fatalf("proxySetFn calls = %v, want [127.0.0.1:9050]", calls)
	}

	proxyPortProbe = func() string { return "9050" }
	s.proxyCheck()
	if len(calls) != 1 {
		t.Fatalf("port already ready → unexpected re-point: %v", calls)
	}
}

func TestAPIStopAndHuntNoDaemon(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/api/stop", "/api/abort", "/api/hunt"} {
		rec := httptest.NewRecorder()
		s.api(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: status = %d", p, rec.Code)
		}
	}
	// With no daemon reachable, no hunt may be running.
	s.mu.Lock()
	hunting := s.hunting
	s.mu.Unlock()
	if hunting {
		t.Fatal("hunting = true without a daemon")
	}
}

func TestHub(t *testing.T) {
	h := &hub{clients: map[chan string]bool{}}
	ch := h.add()
	h.pub("hello")
	select {
	case m := <-ch:
		if m != "hello" {
			t.Fatalf("msg = %q", m)
		}
	case <-time.After(time.Second):
		t.Fatal("no message delivered")
	}
	h.drop(ch)
	h.pub("again") // must not block or panic
}

// ---------- extension embed ----------

func TestExtensionEmbedded(t *testing.T) {
	for _, f := range []string{"extension/manifest.json", "extension/popup.html",
		"extension/popup.js", "extension/bg.js"} {
		b, err := extensionFS.ReadFile(f)
		if err != nil || len(b) == 0 {
			t.Errorf("%s: err=%v len=%d", f, err, len(b))
		}
	}
	b, err := extensionFS.ReadFile("extension/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["name"] != "torspeed" {
		t.Fatalf("manifest name = %v", m["name"])
	}
}
