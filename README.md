# Mirage
QUIC proxy with mandatory ECH + traffic shaping — makes active probing fail, passive analysis see normal HTTP/3.

## How it works

- **Client** — a local SOCKS5 proxy (default `127.0.0.1:1080`). Apps connect to it; traffic is tunneled over QUIC (UDP 443) to the server, using a Chrome-like TLS fingerprint and ECH.
- **Server** — validates a password-derived token on the first stream and proxies TCP/UDP to the destination. Anything without a valid token (probes, scanners, browsers) is served a cached copy of `masquerade.url` over HTTP/3.
- One binary for both sides: `mirage -config <file>`. The `mode:` field (`server` or `client`) selects the side. Default config path: `/etc/mirage.yaml` (`C:\ProgramData\mirage\config.yaml` on Windows).

## 1. Server (Linux VPS)

Requirements: a domain pointing at the VPS, **UDP 443** open, **TCP 80** open if using ACME, and the clock synced via NTP (tokens tolerate about ±30 s of drift).

Install with `sudo bash install.sh` (binary at `/usr/local/bin/mirage`, config at `/etc/mirage.yaml`, systemd unit `mirage`), or build from source with Go 1.24:

```sh
go build -o mirage ./cmd/mirage
```

`/etc/mirage.yaml`:

```yaml
mode: server
password: "long-random-secret"
listen: ":443"

acme:                               # automatic Let's Encrypt cert
  domain: "proxy.example.com"
  email: "you@example.com"
  cache_dir: "/etc/mirage/acme-cache"
# or a manual cert instead of acme:
# tls:
#   cert: "/etc/mirage/server.crt"
#   key:  "/etc/mirage/server.key"

masquerade:
  url: "https://www.example.org"    # must be reachable when the server starts

ech:
  public_name: "cloudflare.com"     # outer SNI visible to observers
  key_file: "/etc/mirage/ech.pem"   # persist so the ECH config survives restarts
```

Start it and grab the ECH config from the log:

```sh
systemctl enable --now mirage
journalctl -u mirage | grep ech_config
# ECH config for clients (ech_config): AEX+DQBB...
```

## 2. Client

`client.yaml`:

```yaml
mode: client
server: "proxy.example.com:443"     # use the domain, not an IP: the cert is verified against it
password: "long-random-secret"
ech_config: "AEX+DQBB..."           # base64 from the server log (optional, recommended)
socks5_listen: "127.0.0.1:1080"
traffic:
  profile: browse                   # browse | video | download | "" (disables shaping)
```

```sh
./mirage -config client.yaml
```

The server certificate is verified against the system CA store, so it must be publicly trusted (ACME is easiest); self-signed certs won't work.

## 3. Use it

Point your browser or OS at the SOCKS5 proxy `127.0.0.1:1080` (enable remote DNS / "proxy DNS when using SOCKS v5"). Check it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me   # prints the server's IP
```

Opening `https://proxy.example.com` in a normal browser should show the masquerade site.

Supported SOCKS5 commands: CONNECT (TCP) and UDP ASSOCIATE (packets up to ~1150 bytes, the QUIC datagram limit). BIND is not supported.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Proxied connections close immediately | wrong password, clock drift over 30 s, or client and server on different versions |
| `ECH config not found` warning | `ech_config` is empty; the tunnel works but without ECH |
| TLS / certificate error on the client | `server` is an IP, or the cert isn't publicly trusted |
| Server exits at startup | `masquerade.url` unreachable, or port 80/443 already in use |

## Traffic module
assisted by Claude Opus 4.7
