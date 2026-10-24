# torspeed — Speed Optimization Research
*Deep research against primary sources only. Repo state verified against `main.go` (see "Verified implementation" at the bottom). Findings ranked by expected throughput impact.*

## Ranked summary

| # | Optimization | Expected gain | Effort | Risk |
|---|---|---|---|---|
| 1 | **Conflux: verify + prefer `Conflux=1` exits** | Up to ~2× on guard/middle-bound paths (est.) | Low | Low |
| 2 | **EXTENDCIRCUIT pre-built warm circuits** | −30–50% hunt wall-clock; kills slow-start bias (est.) | Medium | Low |
| 3 | **Fixed guard+middle across candidates** | Removes path-lottery noise → truer exit ranking | Low (with #2) | Low |
| 4 | **Onionoo pre-ranking (utilization + overload)** | Better candidates → higher best, fewer probes | Medium | Low |
| 5 | **Conflux-aware warm-up after pinning** | Verification reflects real browser speed | Low | None |
| 6 | **Adaptive stream count (3→6 on fast exits)** | +10–30% on high-capacity exits (est.) | Low | None |
| 7 | CircuitBuildTimeout tightening | Marginal wall-clock | Low | Medium — not recommended as-is |
| 8 | Guard handling (EntryNodes/UseEntryGuards) | — | — | **Do not do** (anonymity) |
| 9 | StrictNodes/ExitNodes fallback detection | Correctness, not speed | Low | None |
| 10 | Brave torrc injection | Impossible → use SETCONF (status quo) | — | — |
| 11 | Parallel candidate measurement | — | — | **Not recommended** (shared downlink = unfair) |

---

## 1. Conflux — the single biggest throughput lever

**What it is.** Conflux (prop 329) splits one logical circuit across **two legs that terminate at the same exit** but use **different guards and different middles**. The exit links the legs (`RELAY_CONFLUX_LINK`, sent "from the OP to the exit/service in order to link circuits together at the end point") and multiplexes downlink data across both legs to maximize throughput; the client uses the lower-RTT leg for uplink. Diagram in the proposal shows both legs converging on one `Exit` relay.

**Why it matters for torspeed.** Your bottleneck on a pinned exit is usually *not* the exit — it's the single guard/middle path (the tool's own comment notes "the fastest exits are the most contested"). Conflux gives the *same pinned exit* a second independent path: 2 guards + 2 middles worth of capacity. This is exactly the "path lottery" a single circuit can't escape.

**Status on 0.4.9.x (Brave's bundled tor).**
- Shipped since tor 0.4.8.1-alpha; enabled network-wide via consensus param `cfx_enabled` (code default 1). Client option: `ConfluxEnabled 0|1|auto` — default `auto` = follow consensus. `ConfluxClientUX` default `throughput` (correct for torspeed's use case).
- Consensus params: `cfx_max_prebuilt_set` (code default 3 sets), `cfx_num_legs_set` (default 2), `cfx_low_exit_threshold` (default 6000 = 60% of exits must support it before >1 set is pre-built), `cfx_max_linked_set` (default 10).
- **C-Tor builds conflux sets *preemptively only*** — "conflux sets are never built on-demand"; if the pre-built pool is empty, normal circuits are used.
- A leg only works if the **exit advertises `Conflux=1`** in its descriptor `proto` line (verified in live CollecTor descriptors: `proto Conflux=1 Cons=1-2 …`).
- tor Browser / Brave shipping 0.4.9.x: conflux client code is present; check `GETCONF ConfluxEnabled` + the consensus `params` line.

**Interaction with `ExitNodes` pinning.** The conflux *set* picks one exit via normal path selection → it honors `ExitNodes`. **If the pinned exit lacks `Conflux=1`, conflux silently can't engage** — the browser gets ordinary circuits. So candidate screening should prefer (or at least record) conflux support.

**Implementation sketch for torspeed.**
```text
// per candidate, once (cache it):
lines, _ := c.getinfo("desc/id/" + fp)        // server descriptor
cfx := containsProto(lines, "Conflux=1")      // parse "proto" line
// prefer conflux-capable exits when scores are within ~15%;
// also tag the pinned result "conflux-capable" in the UI.
```
Check daemon-side state once per hunt:
```text
GETCONF ConfluxEnabled                          // want auto|1
GETINFO status/fresh-microdesc-consensus        // header "params" line:
                                                // cfx_enabled=1 cfx_max_prebuilt_set=3 …
GETINFO circuit-status                          // PURPOSE=CONFLUX_LINKED legs
```
(`exitFP()` already accepts `PURPOSE=CONFLUX_LINKED` — main.go:848.)

**Cost/risk.** Low. Legs share the exit but not guard/middle → strictly more path capacity. Caveat: conflux sets are pre-built; right after `SETCONF ExitNodes` the pool holds sets for *other* exits — the conflux benefit arrives over ~30–60 s (see #5). Also note a fixed bug relevant here: 0.4.8.13 fixed conflux prebuilding ignoring predicted ports (idle tor churned circuits every 30 s) — fine on 0.4.9.

**Sources:**
- https://spec.torproject.org/proposals/329-traffic-splitting.html (design, handshake, consensus params, "never built on-demand", same-exit linking, different guards/middles)
- https://gitlab.torproject.org/tpo/core/tor/-/raw/tor-0.4.8.11/ChangeLog (0.4.8.7: "splits traffic across two circuits to Exits that support the protocol … Exit … fully utilizing both circuits in a multiplexed fashion … pre-built only")
- https://manpages.debian.org/trixie/tor/tor.1.en.html (`ConfluxEnabled`, `ConfluxClientUX`)
- https://fossies.org/linux/tor/src/core/or/conflux_params.c (param defaults: enabled=1, legs=2, prebuilt=3, threshold=6000)
- https://spec.torproject.org/tor-spec/relay-cells.html (CONFLUX_LINK/LINKED/SWITCH cell ops)
- https://spec.torproject.org/proposals/354-relaxed-restrictions.html ("Different Guards / middles for each leg in a conflux set … the chosen Exit of this conflux set" — single exit per set)
- https://gitlab.torproject.org/tpo/core/tor/-/raw/tor-0.4.8.22/ChangeLog (0.4.8.13 prebuilt-pool fix; 0.4.8.19 XOFF/conflux fix)
- CollecTor descriptor sample (proto line): https://collector.torproject.org/recent/relay-descriptors/server-descriptors/2026-09-12-01-01-35-server-descriptors

---

## 2. Pre-built warm circuits via `EXTENDCIRCUIT` — eliminate per-candidate build time

**What it is.** The control protocol lets a controller build circuits with a fully explicit path:
```text
EXTENDCIRCUIT 0 $guardfp,$middlefp,$exitfp "purpose=general"   → 250 EXTENDED <id>
```
With `CircuitID=0` tor builds a new circuit on the given path; `purpose=general` makes it eligible for stream attachment (including the browser's later traffic — it's a real circuit, not a throwaway). Circuits build asynchronously; issue all of them up front and watch `SETEVENTS CIRC` for `BUILT`.

**Two distinct wins:**
- **Wall-clock:** today each candidate costs circuit-build + TTFB inside the probe. Build all 8 candidates' circuits **in parallel** (each with an explicit `guard,middle,exit` path — no `ExitNodes` needed to direct the build) — the whole pool is hot in ~2–4 s total. `MaxClientCircuitsPending` default is 32, so 8–16 concurrent builds are fine.
- **Warm-up:** a circuit that finished building and already passed some cells is past the congestion-control ramp (see #5/#7): the steady-state window sees honest throughput immediately instead of paying the 1–1.5 s Vegas ramp per sample.

**Attachment without `__LeaveStreamsUnattached` (the simple, low-risk path).** You don't need `ATTACHSTREAM` at all for the sequential hunt: keep `SETCONF ExitNodes=$fp` per candidate; any clean circuit to that exit is a valid attachment target — and your pre-built ones *are* clean circuits to it. To make attachment deterministic, close competing clean circuits to that exit (`closeStaleCircuits` already walks `GETINFO circuit-status`; extend it to keep specific circuit IDs rather than any circuit ending at `keepFP`). Alternatively, race-free exact control exists: `SETCONF __LeaveStreamsUnattached 1` + `SETEVENTS STREAM` + `ATTACHSTREAM streamid circid` — but that's global: the *browser's* streams would also stall until attached (must forward them with `ATTACHSTREAM sid 0` = hand back to tor). Recommend the ExitNodes+prebuilt route; keep `__LeaveStreamsUnattached` out of it.

**Verification hook already available:** after the SOCKS connect, `GETINFO stream-status` gives `StreamID Status CircuitID Target` → map to `circuit-status` → confirm last hop = candidate. Cheap sanity check that the probe really used the intended circuit.

**Cost/risk.** Low. Controller-built paths "may violate some [path] constraints" by design (path-spec explicitly allows controller override). These circuits are cannibalizable general circuits, so leftover ones just serve normal traffic. `EXTENDCIRCUIT`-built circuits can't become conflux legs (conflux sets are tor-built only) — so measure mode and browser mode differ slightly; see #5.

**Sources:**
- https://spec.torproject.org/control-spec/commands.html — `EXTENDCIRCUIT` (path optional; `purpose=general|controller`), `ATTACHSTREAM` (only to `BUILT` circuits; `ATTACHSTREAM sid 0` = auto-attach), `circuit-status`/`stream-status` formats
- https://spec.torproject.org/control-spec/implementation-notes.html — `__LeaveStreamsUnattached` (controller must attach every stream; data never routed otherwise), `__DisablePredictedCircuits`
- https://spec.torproject.org/path-spec/general-operation.html — "path selection … can be overridden by a controller (with EXTENDCIRCUIT and ATTACHSTREAM)"
- https://manpages.debian.org/bookworm/tor/tor.1.en.html — `MaxClientCircuitsPending` default 32

---

## 3. Fixed guard + middle across candidates — measure the *exit*, not the lottery

**What it is.** Today each sample draws a random middle (fresh SOCKS isolation) *and* rides whatever the single in-use guard is — so candidate scores conflate exit quality with path luck. With `EXTENDCIRCUIT` you choose the full path: **hold guard and middle constant, vary only the exit**. Then the ranking measures the exit's own contribution — the thing the pin actually controls. (The browser's eventual speed still includes its own guard/middle lottery, which is why conflux — #1 — matters for production.) Optionally run a second pass with a different middle to separate "exit capacity" from "one lucky middle".

**Expected gain.** Ranking fidelity, not raw speed: fewer samples needed for the same confidence (the current 2-sample mean over random paths is noisy), fewer wasted probes, and the "average because middles are random" workaround (main.go:1294) gets upgraded into a controlled experiment.

**Implementation sketch.**
```text
guardfp  = current primary guard   // parse first hop of any BUILT general circuit
middlefp = one random Stable+Fast+Running middle from top-200
for cand in candidates:
    EXTENDCIRCUIT 0 $guardfp,$middlefp,$cand.fp purpose=general   // parallel
wait for all BUILT (SETEVENTS CIRC or poll circuit-status)
for cand in candidates:
    SETCONF ExitNodes=$cand.fp
    probe()                                                      // attaches to the warm prebuilt circ
```
**Sources:** same control-spec/path-spec links as #2; guard default-of-1 below.

---

## 4. Onionoo pre-ranking — replace "random from top-60" with a scored shortlist

**What it is.** `topExits()` currently sorts by the consensus `w Bandwidth=` value and draws 8 at random. Onionoo adds congestion-relevant signals the consensus doesn't have:

| Field | Doc | Signal for ranking |
|---|---|---|
| `measured` (details) | bool: ≥3 bwauths measured it | unmeasured ⇒ weight is clipped/unreliable — deprioritize |
| `consensus_weight`, `exit_probability` (details/weights) | selection probability | already proxy for capacity |
| `observed_bandwidth`, `bandwidth_rate/burst` (details) | relay-reported capacity | headroom sanity |
| `read_history`/`write_history` (bandwidth doc) | actual traffic over 3d/1w/1m | **utilization** — `read_history` ÷ capacity ≈ contestedness; prefer high capacity with *low* utilization |
| `overload_ratelimits`, `overload_fd_exhausted` (bandwidth doc) | relay hit its own limits | **direct congestion evidence** — skip or deprioritize |
| `as_number`, `as_name`, `country`, `latitude/longitude` (details) | routing/geo | optional AS/geo-aware tie-breaks (see #8 papers) |
| `protocols` (details) | supported subprotocols incl. `Conflux` | pre-filter #1 without per-relay `desc/id` fetch |

Suggested score: `score = exit_probability × capacity_utilization_factor × (measured?1:0.6) × (overload?0.3:1) × (conflux?1.15:1)`, draw weighted-random from top ~40.

**Privacy.** A clearnet GET to `onionoo.torproject.org` reveals only "this IP fetches public Tor metadata" — mild. Better: fetch *through the daemon's own SOCKS* (`dialSocks` already exists; a Tor-window daemon is required anyway). It's one JSON request per hunt, cacheable for ~30 min (Onionoo updates hourly; relay data lags descriptor publication up to ~18 h for bandwidth docs).

**Cost/risk.** Low. Fail-soft: if fetch fails, keep current random draw. Fields are all documented optional — tolerate missing.

**Sources:**
- https://metrics.torproject.org/onionoo.html (protocol doc: methods, field semantics, `measured` = "consensus weight … based on a threshold of 3 or more measurements by Tor bandwidth authorities")
- https://github.com/torproject/metrics-web/blob/master/src/main/resources/web/jsps/onionoo.jsp (canonical field list; `as_number`, `measured`, consensus weight "unit … currently kilobytes per second")
- https://networkstatusapi-72c5c5.pages.torproject.net/onionoo.html (new-API field list incl. `guard/middle/exit_probability`, `overload_*`, `read_history`)
- Onionoo `measured` rationale (unmeasured relays clipped to ~20 KB/s): https://archive.torproject.org/websites/lists.torproject.org/pipermail/tor-dev/2015-August/009355.html

---

## 5. Conflux-aware warm-up after pinning (and for the verify probe)

**What it is.** Two related warm-up facts:
- Tor's per-circuit congestion control (prop 324; `cc_alg` default **2 = Tor Vegas**; negotiated via `FlowCtrl` subprotocol) starts each circuit in slow start. Vegas ramps while estimating BDP — the first ~1–2 s of a cold circuit under-represent steady-state.
- Conflux sets are **pre-built only**; after `SETCONF ExitNodes`, sets for the new exit fill the prebuilt pool on the ~30 s `NewCircuitPeriod` cycle. A probe or browser stream in the first seconds lands on an ordinary single circuit.

**Current code is mostly right** (main.go:679–700: window opens after `w = min(span/3, 1.5 s)` — correctly excludes build+TLS+slow-start). Improvements:
1. With pre-built circuits (#2), push a small warm-up transfer (~0.5–1 MB) through each circuit right after `BUILT` — the measurement window then opens on a circuit past the Vegas ramp.
2. After pinning a `Conflux=1` exit, keep the existing 4 s sleep for the *pin* verification, but add an optional delayed re-verify (~60 s, or on next status poll) so the reported number reflects the 2-leg speed the browser will actually settle into — otherwise `--hunt` under-reports conflux exits and over-reports single-circuit-lucky exits.
3. While hunting, `GETINFO circuit-status` legs with `PURPOSE=CONFLUX_LINKED` tell you the probe actually got a linked set.

**Cost/risk.** None — strictly better measurement fidelity.

**Sources:**
- https://spec.torproject.org/proposals/324-rtt-congestion-control.html (`cc_alg` 0=fixed,1=Westwood,**2=Vegas default**; Vegas queue/BDP model)
- https://blog.torproject.org/congestion-contrl-047/ (0.4.7.7 shipped it; "eliminate the speed limit" — relay upgrade required end-to-end)
- https://spec.torproject.org/proposals/329-traffic-splitting.html §"Pre-Building Sets" (pre-built only; empty pool → normal circuits)
- https://manpages.debian.org/trixie/tor/tor.1.en.html (`NewCircuitPeriod` default 30 s)

---

## 6. Adaptive stream count — 3 streams under-saturate good paths

**What it is.** Probes use `streams: 3` everywhere (main.go:1241). A real browser keeps far more sockets open; on an uncongested fast exit (or a 2-leg conflux set) 3 streams can leave the circuit window under-filled. Cheap adaptive step: run the probe at 3 streams; if the windowed rate plateaus *and* `res.mbps` ≥ some threshold (e.g., 25 Mbit/s) or ≥ target, run one extra confirmation sample at 6 streams — rank by the best of the two. Keep 3 as the floor (slow exits converge fast anyway).

**Cost/risk.** None — more bytes burned only on already-fast candidates. Don't raise unconditionally: extra parallel streams on congested exits just add queue.

**Source:** browser-vs-single-stream rationale is already in README ("a single Tor stream is window-limited; browsers use many"); prop 324 windowing behavior above.

---

## 7. `CircuitBuildTimeout` / `LearnCircuitBuildTimeout` — marginal; prefer #2 instead

**What it is.** `LearnCircuitBuildTimeout` (default 1) makes tor learn a Pareto-distributed build timeout from observed builds (`cbt*` consensus params: `cbtquantile`, `cbtclosequantile`, `cbtmintimeout`, `cbtinitialtimeout`, `cbtmaxtimeouts`, `cbtnummodes`, `cbtrecentcount`, `cbtmincircs`, `cbttestfreq`, `cbtmaxopencircs`, `cbtdisabled`). With learning off, `CircuitBuildTimeout` (default 60 s) is the fixed cap; tor warns if set under ~10 s (build failure risk).

**Honest assessment.** Tightening CBT (e.g., `SETCONF LearnCircuitBuildTimeout=0` + `CircuitBuildTimeout=10`) only shortens the *wait for doomed builds*; it doesn't make fast circuits faster, and under `ExitNodes` pinning a slow build is often a slow path to the *same* exit — retrying just burns time. **Pre-building (#2) removes this problem entirely.** If you still want it, apply only during the hunt and `RESETCONF` after. Not recommended as a default.

**Sources:**
- https://manpages.debian.org/trixie/tor/tor.1.en.html (`CircuitBuildTimeout` 60 s default; `LearnCircuitBuildTimeout`; `CircuitStreamTimeout`)
- https://spec.torproject.org/param-spec.html (`cbt*` consensus params → path-spec §2.4.5)
- https://tpo.pages.torproject.net/core/doc/tor/config_8c.html (`RECOMMENDED_MIN_CIRCUIT_BUILD_TIMEOUT` = 10)

---

## 8. Guards — hands off `EntryNodes`/`UseEntryGuards`; get the same effect via #3

**Facts.** `NumEntryGuards` default 0 → learn from consensus `guard-n-primary-guards-to-use` → **default 1**: all your circuits share one long-term guard. A bad guard bottlenecks *every* circuit incl. the eventual browser traffic — guard choice genuinely dominates single-circuit throughput.

**What NOT to do.**
- `UseEntryGuards 0`: destroys the guard anonymity model (each circuit a fresh, possibly adversarial, first hop). Never ship.
- `EntryNodes` pinning: global, and without `StrictNodes` it's only a *preference*; pinning a "measured-fast" guard for production traffic narrows the anonymity set and fights tor's guard rotation — a privacy regression for throughput.
- `NumEntryGuards 1` is already effectively the in-use default.

**What TO do.** Use the #2/`#3` mechanism: EXTENDCIRCUIT lets you *fix* the guard during measurement (controlled comparison) or deliberately pick a high-capacity guard for the test path — zero config change, zero persistence, zero anonymity change for the user's real traffic. And conflux (#1) is the *blessed* way to get a second guard in production.

**Sources:**
- https://manpages.debian.org/bookworm/tor/tor.1.en.html (`NumEntryGuards` default 0 → consensus `guard-n-primary-guards-to-use` → 1; `UseEntryGuards`; `GuardLifetime`)
- https://spec.torproject.org/param-spec.html (guard consensus params)
- https://spec.torproject.org/proposals/329-traffic-splitting.html (legs "SHOULD NOT share the same Guard relay")

---

## 9. `ExitNodes` fallback caveat — pin is a *preference*, detect evasion

**What it is.** The code comment (main.go:822) says "StrictNodes does not apply to ExitNodes (exit circuits are always strict)". The manpage is more nuanced: `ExitNodes` "are treated only as preferences unless StrictNodes is also set" — though tor since 0.2.2 is *aggressive* about honoring them ("only falls back to others if they're all down and StrictNodes is not set" — and changes to `*Nodes` options mark and discard all origin circuits). Practical consequence: if the pinned exit goes down or its policy stops covering a port, tor may route through other exits — the "pin" silently dissolves.

**Fix (cheap).** You already have the pieces: `lastCircuitExit()` — surface a "pin evaded" state when `pinnedExit() != ""` but the newest BUILT circuit exits elsewhere. Optional hardening for users who want fail-closed pinning: document `SETCONF StrictNodes=1` (careful — it also upgrades `ExcludeNodes`/`EntryNodes` to absolute, which is exactly why the code avoids it; fine to leave as-is).

**Sources:**
- https://web.archive.org/web/20110114033509/www.torproject.org/docs/tor-manual.html.en (`StrictNodes` semantics — wording unchanged since)
- https://archives.seul.org/or/cvs/Dec-2009/msg00361.html (tor 0.2.2 change log: `*Nodes` changes discard origin circuits; aggressive honoring, fallback only when all listed nodes down)

---

## 10. Brave's bundled tor — no torrc injection; `SETCONF` is the supported channel

**Facts.** Brave ships tor via the **"Brave Tor Client Updater" component** (per-platform component ID, e.g. `cldoidikboihgcjfkhdeidbpclkineef`; your `cpoalefficncklhjfpglfiplenlpccdb` is the Windows one). The component directory — containing the tor binary **and `tor-torrc`** — lives under a *versioned* path (`…/<id>/1.0.xx/tor-torrc`), is treated read-only by Brave, and is **replaced on every component update** (updater checks ~every 5 h). Brave launches tor with `-f <component>/tor-torrc` plus `--DataDirectory`, `--ControlPortWriteToFile`, `--CookieAuthFile`, `--PidFile` and the `tor/watch` dir — there is **no user-torrc/`--defaults-torrc` hook** and Brave states it doesn't support custom tor config.

**Consequences for torspeed.**
- Editing `tor-torrc` = lost on next component update (and possibly integrity-checked). **Don't.**
- `SETCONF` is already your injection channel — extend it for `ConfluxEnabled 1`, `ConfluxClientUX throughput` if ever needed; it's transient (dies with the Brave-tor process), consistent with the existing pin model.
- **Do not `SAVECONF`** — it writes into that component torrc, can conflict with Brave's own launch expectations, and still dies on update.
- For the *own* spawned daemon (`spawnTor`, main.go:933) you control the command line — add `--ConfluxEnabled 1` etc. there for a persistent default on the daemon torspeed owns.

**Sources:**
- Brave issue #40370, comment by Brave tor maintainer (`darkdh`): component dir "for on the fly incremental updating Tor daemon and its torrc … supposed to be readonly"; tor/watch = pidfile + controlport + cookie — https://github.com/brave/brave-browser/issues/40370
- Component updater mechanics: https://github.com/brave/brave-browser/wiki/Brave-Components
- Brave tor binary at 0.4.9.x via component: https://github.com/brave/brave-browser/issues/56044 (tor 0.4.9.9 test log showing `Read configuration file "…/cldoidikboihgcjfkhdeidbpclkineef/1.0.84/tor-torrc"`)
- brave-core tor control/launcher: https://github.com/brave/brave-core/blob/master/components/tor/tor_control.h ; https://deepwiki.com/brave/brave-core/9.4-tor-integration

---

## 11. NEWNYM / live-connection semantics — current handling is correct

`SIGNAL NEWNYM` marks all dirty circuits unusable for *new* streams and clears the client DNS cache; **it never kills in-flight streams** and tor rate-limits it (`MAX_SIGNEWNYM_RATE` = 10 s). Your `closeStaleCircuits()` + `CLOSECIRCUIT` for non-winner BUILT circuits (main.go:864) is exactly the right complement — keep-alive/HTTP-2 connections are forced onto the pinned exit, which NEWNYM alone wouldn't do. No change needed; just note the 10 s rate limit if you ever add NEWNYM inside the per-candidate loop (don't — SOCKS isolation already gives fresh circuits).

**Sources:**
- https://github.com/torproject/torspec/blob/main/control-spec.txt (SIGNAL NEWNYM: "Switch to clean circuits … new application requests don't share any circuits with old ones … MAY rate-limit")
- https://archives.seul.org/tor/commits/Feb-2007/msg02382-adjacent: r9615 (`MAX_SIGNEWNYM_RATE 10`, pending-signal behavior)
- https://spec.torproject.org/path-spec/attaching-streams-to-circuits.html (unattached streams abandoned after `SocksTimeout` ≈ 2 min)

---

## 12. Parallel measurement — do NOT measure candidates in parallel

`ExitNodes` is global per-daemon, so parallel per-exit measurement requires ATTACHSTREAM onto pre-built circuits (`EXTENDCIRCUIT` + `__LeaveStreamsUnattached`) — technically possible, but parallel probes **share the downlink**, so their absolute rates are mutually suppressed and the ranking becomes meaningless. The codebase already encodes this principle for daemons (`compareDaemons`: "parallel probes would share the downlink and make the comparison unfair", main.go:1717). **Use parallelism only for circuit *building* (#2), keep measurement sequential.** A possible exception: a quick parallel *liveness/reachability* screen (tiny 1 MB budget) purely to drop dead candidates — relative finish order under identical contention is a fair-ish reject signal.

**Source:** control-spec `__LeaveStreamsUnattached` note; path-spec stream-attach section (links above).

---

## 13. Academic signals for exit ranking — what to borrow

| Work | Signal usable by torspeed |
|---|---|
| **Snader & Borisov, "A Tune-up for Tor"** (NDSS 2008) + IEEE TDSC 2010 extension | Validates the core thesis: *self-reported/consensus bandwidth is a poor throughput proxy* — they replaced it with **opportunistic client-side measurement** (i.e., exactly what a hunt does). Also: tunable perf-vs-anonymity weighting → justification for letting users pick pool size. https://www.ndss-symposium.org/ndss2008/a-tune-up-for-tor-improving-security-and-performance-in-the-tor-network/ ; https://doi.org/10.1109/tdsc.2010.40 |
| **PredicTor** (Barton et al.; IEEE S&P'17 poster → ACM TOPS 2025) | Random-Forest classifier on per-relay features (**AS, country, consensus BW per hop**) predicts fast vs slow paths; +11–23% over vanilla, dynamically avoids congested relays. Takeaway: features for the #4 scorer — AS/CC/bw of *all three hops*, not just the exit. https://arxiv.org/html/1805.01977 ; https://doi.org/10.1145/3723356 |
| **LASTor** (Akhoondi, Yu, Madhyastha — IEEE S&P 2012; TON 2013) | AS-aware + geography-aware path choice cut median latency ~25%; proves path *location* matters — supports an AS/geo tie-break term in the scorer (and avoids same-AS entry/exit for anonymity as a bonus). https://doi.org/10.1109/sp.2012.35 |
| **CAR — Congestion-Aware Routing** (Wang/Goldberg, cited in PredicTor as previous SOTA) | Opportunistic circuit-congestion probing at build time ≈ your warm-up probe; reinforces that measured-per-circuit beats static weights. (via PredicTor paper, above) |
| "ASAP" | No primary-source Tor paper by that name found; closest match is the AS-aware path-selection line (LASTor/DeNASA/Counter-RAPTOR). Flagged as unresolved — if the user meant a specific paper, need the citation. |

Bottom line from the literature: static consensus weight is the weakest predictor; **measured utilization + per-hop features + live probing** is the established winner — which is precisely the #2/#3/#4 design above.

---

## Verification recipes (run against the live daemon)

```text
GETCONF ConfluxEnabled                              # auto|1 wanted
GETCONF ConfluxClientUX                             # throughput (default, wanted)
GETCONF SocksPort                                   # note listeners before adding any
GETINFO status/fresh-microdesc-consensus            # header "params …" → cfx_enabled, cfx_max_prebuilt_set, cc_alg, cbt*
GETINFO desc/id/$FP                                 # "proto … Conflux=1 …" → exit supports conflux
GETINFO circuit-status                              # PURPOSE=CONFLUX_LINKED legs during browsing
GETINFO stream-status                               # StreamID Status CircuitID Target → attach audit
SETEVENTS CIRC STREAM                               # watch BUILT + stream attachment live
```

## Verified implementation facts (main.go)

- Control: SAFECOOKIE/cookie auth; Brave `tor/watch/controlport` dynamic port, TB 9151, system 9051 (L208–303).
- Hunt: `topExits(c,60)` on consensus `w Bandwidth=`, random draw of `--candidates` (default 8), `SETCONF ExitNodes=$fp` per candidate, `isolate: isolationToken()` → fresh circuit via `IsolateSOCKSAuth` (on by default), 3 streams, 20 MB, 2 samples averaged (L780–818, 1219–1318).
- Early-abort below 70% of best; ±5%-converged early stop (L1252–1264). Steady-state window `min(span/3,1.5 s)` (L679–700).
- Pin → `CLOSECIRCUIT` non-matching BUILT GENERAL/CONFLUX_LINKED circuits → `NEWNYM` → verify (L1319–1345); `exitFP` already parses `CONFLUX_LINKED` (L848).
- PAC extension: mandatory `SOCKS5` list, loopback-only `DIRECT`, fail-closed (extension/bg.js:23–33).

## Sources index (all primary)

- Prop 329 Conflux: https://spec.torproject.org/proposals/329-traffic-splitting.html
- Prop 324 congestion control: https://spec.torproject.org/proposals/324-rtt-congestion-control.html ; https://blog.torproject.org/congestion-contrl-047/
- tor manpage: https://manpages.debian.org/trixie/tor/tor.1.en.html
- Consensus params: https://spec.torproject.org/param-spec.html
- Control spec: https://spec.torproject.org/control-spec/commands.html ; implementation notes: https://spec.torproject.org/control-spec/implementation-notes.html
- Path spec: https://spec.torproject.org/path-spec/ (general-operation, attaching-streams, path-selection-constraints)
- conflux_params.c defaults: https://fossies.org/linux/tor/src/core/or/conflux_params.c
- tor ChangeLog 0.4.8.x: https://gitlab.torproject.org/tpo/core/tor/-/raw/tor-0.4.8.22/ChangeLog
- Onionoo: https://metrics.torproject.org/onionoo.html ; https://github.com/torproject/metrics-web/blob/master/src/main/resources/web/jsps/onionoo.jsp
- Brave: https://github.com/brave/brave-browser/issues/40370 ; https://github.com/brave/brave-browser/wiki/Brave-Components ; https://github.com/brave/brave-browser/issues/56044
- Papers: Snader&Borisov NDSS'08 https://www.ndss-symposium.org/ndss2008/a-tune-up-for-tor-improving-security-and-performance-in-the-tor-network/ ; TDSC'10 https://doi.org/10.1109/tdsc.2010.40 ; PredicTor https://arxiv.org/html/1805.01977 + https://doi.org/10.1145/3723356 ; LASTor https://doi.org/10.1109/sp.2012.35

---

## Verification appendix (checked against tor 0.4.9.14 source + live isolated instance)

Several claims above were re-checked before implementation; half did not
hold:

- **#1 Conflux prefiltering: pointless.** Live: 2729/2729 exits support
  conflux; all top-60 do. With a pin set, tor builds conflux sets to the
  pinned exit automatically (4 linked sets observed). No filtering needed.
- **`GETINFO desc/id` for conflux check fails** on microdescriptor clients:
  `552 We fetch microdescriptors, not relay descriptors`. `md/id` is the
  right key, but irrelevant after the point above.
- **`status/fresh-microdesc-consensus` does not exist** in
  control_getinfo.c; `status/enough-dir-info` does and is used by the pin
  watchdog instead.
- **#2/#3 SETCONF-based candidate switching kills prebuilt circuits**:
  `options_set` → `exitnodes` transition triggers
  `circuit_mark_all_unused_circs` for circuits not allowed by the new
  options (config.c:2335-2360, verified live). Any prebuild/warm circuit
  dies at the next `SETCONF ExitNodes`. The v0.6 probe-daemon design
  sidesteps this entirely: per-candidate pinning happens on the probe.
- **#5 "conflux needs 30-60 s" is wrong**: second leg linked in ~2.3 s live.
- **#9 inverted**: `ExitNodes` *is* strict without `StrictNodes`
  (tor.1.txt:2175, circuitbuild.c:1787/1902). Real risk is the opposite
  direction: a pinned exit that dies leaves the browser with **no** exit
  circuits → pin watchdog releases it.
- **.exit MAPADDRESS isolation works** (verified live: probe streams exit
  via mapped relay while `ExitNodes` pin stays). Superseded by the probe
  daemon, which needs no mappings at all.
- **Top-60 subnet concentration confirmed live**: 22 relays in
  45.66.35.0/24, 14 in 185.220.100.0/24 – 60 % of the pool on two uplinks.
  → `pickDiverse` (/24) in the hunt draw.
