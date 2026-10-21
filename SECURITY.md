# Security Policy

torspeed handles Tor control authentication cookies, configures browser and
system proxies, and routes traffic through Tor. If you find a vulnerability
– e.g. a way local processes or web pages could reach the local API, a leak
that bypasses the fail-closed routing, or anything else – please report it
privately:

- Use **GitHub → Security → Report a vulnerability** (private advisory), or
- open an issue **without** exploit details and ask for a private channel.

Please do not disclose publicly before a fix is out.

## Scope notes

- The local API binds to `127.0.0.1` only – by design.
- Browser routing is fail-closed by design; if you ever observe a direct
  (clearnet) fallback while it is enabled, that is a bug – please report it.
- torspeed does **not** provide Tor Browser-grade anti-fingerprinting; that
  limitation is documented and not a vulnerability.
