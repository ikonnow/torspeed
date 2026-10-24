# Changelog

## v0.6

- Hunts measure on a dedicated probe tor daemon (`~/.torspeed/probe`,
  spawned automatically) – the per-candidate re-pinning no longer
  abandons the browser's circuits: browsing is not interrupted.
- Graceful exit switch: the pinned exit's circuit is warmed up first,
  then stale circuits are swept; a 10 s watcher sweeps late conflux
  stragglers while a pin is active. No more `SIGNAL NEWNYM`, no reload.
- Per-sample exit verification: each isolated sample's circuits are
  checked against the pinned candidate (stale conflux sets can carry
  the previous exit) and always closed again.
- **Boost**: optional background optimizer keeps sampling exits on the
  probe daemon; switches the pin only at ≥15 % confirmed improvement,
  prunes everything without potential, backs off 20 s → 5 min, and
  stops itself after 60 min without improvement. Toggle in the
  popup/dashboard or `POST /api/boost?on=0|1`.
- Measure re-rolls a bad circuit: a result clearly below the pinned
  score closes the no-auth circuits on the pin, warms again, re-measures.
- Status API gains `boost`, `boost_auto`, `boost_probes`,
  `boost_switches`, `probe`.

## v0.5

- Fail-closed browser routing via PAC script (`Route browser via Tor`):
  SOCKS5 entries for every ready daemon, loopback stays DIRECT,
  no clearnet fallback; WebRTC forced to `disable_non_proxied_udp`.
- System proxy toggle (macOS `networksetup`, GNOME `gsettings`),
  auto-re-pointed to a ready daemon every 30 s while `--serve` runs.
- `--compare`: measures all discovered daemons sequentially, activates
  the winner.
- Popup/dashboard: live throughput, hunt progress shows fastest score
  so far, toolbar badge follows the leading value.
- API: routes renamed (`/api/vpn` → `/api/proxy`,
  `/api/versus` → `/api/compare`) – re-run `torspeed --install-ext`
  when upgrading.
- `--version` flag; release binaries for macOS (arm64/amd64), Linux
  (amd64/arm64) and Windows (amd64).
