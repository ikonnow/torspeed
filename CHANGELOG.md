# Changelog

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
