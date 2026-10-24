//go:build integration

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIntegrationHuntProbe runs a real hunt against the isolated test
// tor whose control port is TORSPEED_IT_CTRL (browsing daemon). A
// dedicated probe tor is spawned in a temp dir for the measuring.
//
//	TORSPEED_IT_CTRL=127.0.0.1:19051 go test -tags integration \
//		-run Integration -v -timeout 15m
func TestIntegrationHuntProbe(t *testing.T) {
	addr := os.Getenv("TORSPEED_IT_CTRL")
	if addr == "" {
		t.Skip("TORSPEED_IT_CTRL not set")
	}
	d := probeDaemon(addr)
	if d == nil {
		t.Fatalf("no tor control port at %s", addr)
	}
	d.name = "it-browsing"
	dir := t.TempDir()
	probe, cmd, err := spawnProbeTor(dir)
	if err != nil {
		b, _ := os.ReadFile(dir + "/tor.log")
		t.Fatalf("spawnProbeTor: %v\n%s", err, b)
	}
	defer func() {
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	if !waitReady(probe, 180*time.Second) {
		b, _ := os.ReadFile(dir + "/tor.log")
		t.Fatalf("probe not ready; tor.log:\n%s", b)
	}
	t.Logf("probe tor at %s", probe.addr)

	ctx := context.Background()
	best, _ := hunt(ctx, d, huntOpts{
		candidates: 3, samples: 1, maxMB: 5, probe: probe,
		logf: func(m string) { t.Log(m) },
	})
	if best.fp == "" {
		t.Fatal("hunt found no usable exit")
	}

	c, err := d.connect()
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if p := pinnedExit(c); !strings.EqualFold(p, best.fp) {
		t.Fatalf("pinnedExit = %q, want %q", p, best.fp)
	}

	// Late conflux legs may still appear – give them a moment, sweep,
	// then every no-auth BUILT general-purpose circuit must exit via
	// best.fp.
	time.Sleep(6 * time.Second)
	sweepWrongExit(c, best.fp)
	lines, _ := c.getinfo("circuit-status")
	seen := 0
	for _, l := range lines {
		ci, ok := parseCirc(l)
		if !ok || !ci.general() || ci.user != "" {
			continue
		}
		seen++
		if !strings.EqualFold(ci.exit(), best.fp) {
			t.Errorf("circuit %s exits via %s, not %s: %s",
				ci.id, ci.exit(), best.fp, l)
		}
	}
	t.Logf("%d no-auth general circuits all exit via %s", seen, best.fp)

	pc, err := probe.connect()
	if err != nil {
		t.Fatal(err)
	}
	defer pc.close()
	plines, _ := pc.getinfo("circuit-status")
	for _, l := range plines {
		if ci, ok := parseCirc(l); ok && ci.user != "" {
			t.Errorf("probe circuit %s still has SOCKS_USERNAME=%q",
				ci.id, ci.user)
		}
	}
}

// TestIntegrationWatchdog runs the pin watchdog against real tor replies:
// a live top exit must stay pinned, a fingerprint missing from the
// consensus must be released.
//
//	TORSPEED_IT_CTRL=127.0.0.1:19051 go test -tags integration \
//		-run IntegrationWatchdog -v
func TestIntegrationWatchdog(t *testing.T) {
	addr := os.Getenv("TORSPEED_IT_CTRL")
	if addr == "" {
		t.Skip("TORSPEED_IT_CTRL not set")
	}
	d := probeDaemon(addr)
	if d == nil {
		t.Fatalf("no tor control port at %s", addr)
	}
	if !waitReady(d, 180*time.Second) {
		t.Fatal("tor not ready")
	}
	c, err := d.connect()
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	defer unpin(c)
	ex, err := topExits(c, 1)
	if err != nil || len(ex) == 0 {
		t.Fatalf("topExits: %v %v", ex, err)
	}
	s := &server{hub: &hub{clients: map[chan string]bool{}}}

	pin(c, ex[0].fp)
	if s.releaseDeadPin(c, ex[0].fp) {
		t.Fatalf("healthy exit %s released", ex[0].name)
	}
	if p := pinnedExit(c); !strings.EqualFold(p, ex[0].fp) {
		t.Fatalf("healthy pin changed: %q", p)
	}

	dead := strings.Repeat("A", 40) // in no consensus
	pin(c, dead)
	if p := pinnedExit(c); p != dead {
		t.Fatalf("SETCONF of the dead fingerprint failed: %q", p)
	}
	if !s.releaseDeadPin(c, dead) {
		t.Fatal("dead pin kept")
	}
	if p := pinnedExit(c); p != "" {
		t.Fatalf("pin still set after release: %q", p)
	}
	t.Logf("kept live %s, released dead %s…", ex[0].name, dead[:8])
}
