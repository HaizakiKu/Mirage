#!/usr/bin/env bash
set -euo pipefail

REPO="HaizakiKu/mirage"
BIN="/usr/local/bin/mirage"
CFG="/etc/mirage.yaml"
DATA_DIR="/etc/mirage"
SERVICE="/etc/systemd/system/mirage.service"

# ── helpers ───────────────────────────────────────────────────────────────────
info() { echo "  $*"; }
ok()   { echo "  ✓ $*"; }
die()  { echo "  ✗ $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"

# ── detect arch ───────────────────────────────────────────────────────────────
case "$(uname -m)" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="armv7" ;;
    *)       die "Unsupported architecture: $(uname -m)" ;;
esac

# ── fetch latest release tag ──────────────────────────────────────────────────
info "Fetching latest release…"
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' | cut -d'"' -f4)
[[ -n $TAG ]] || die "Could not determine latest release tag."

# ── download binary ───────────────────────────────────────────────────────────
URL="https://github.com/${REPO}/releases/download/${TAG}/mirage-linux-${ARCH}"
info "Downloading mirage ${TAG} (linux/${ARCH})…"
curl -fsSL "$URL" -o "$BIN" || die "Download failed: ${URL}"
chmod +x "$BIN"
ok "Binary installed at ${BIN}"

# ── create data directory ─────────────────────────────────────────────────────
mkdir -p "$DATA_DIR"

# ── write default config (skip if already exists) ─────────────────────────────
if [[ -f $CFG ]]; then
    info "Config already exists at ${CFG} — skipping."
else
    cat > "$CFG" <<'EOF'
# Mirage configuration
# Reference: https://github.com/HaizakiKu/mirage

mode: server   # server | client

# ── Authentication ────────────────────────────────────────────────────────────
password: "your-password-here"

# ── TLS — choose one of the two methods below ─────────────────────────────────

# Method 1: ACME (automatic Let's Encrypt cert)
# Requires a real domain pointed at this server and port 80 open.
acme:
  domain: "example.com"
  email:  ""                          # optional, for expiry alerts
  cache_dir: "/etc/mirage/acme-cache"

# Method 2: Manual cert
# Comment out the acme block above and uncomment this instead.
# tls:
#   cert: "/etc/mirage/server.crt"
#   key:  "/etc/mirage/server.key"

# ── Server ────────────────────────────────────────────────────────────────────
listen: ":443"

masquerade:
  url: "https://www.cloudflare.com"   # HTTP/3 site used as cover traffic

# ── ECH ───────────────────────────────────────────────────────────────────────
ech:
  public_name: "cloudflare.com"       # outer SNI visible to censors
  key_file: "/etc/mirage/ech.pem"     # auto-generated on first start

# ── Traffic shaping ───────────────────────────────────────────────────────────
traffic:
  profile: browse   # browse | video | download

congestion:
  jitter: 0.1       # BBR jitter fraction (0 = off)

# ── Port hopping (optional) ───────────────────────────────────────────────────
# port_hopping:
#   enabled: true
#   port_range: "20000-30000"

# ─────────────────────────────────────────────────────────────────────────────
# CLIENT MODE — replace everything above with the following when mode: client
# ─────────────────────────────────────────────────────────────────────────────
# mode: client
# server: "example.com:443"   # domain name (not an IP): the TLS cert is verified against it
# password: "your-password-here"
# ech_config: ""        # base64 string printed by the server on first start
# socks5_listen: "127.0.0.1:1080"
# traffic:
#   profile: browse
EOF
    chmod 600 "$CFG"
    ok "Config created at ${CFG}"
fi

# ── install systemd service ───────────────────────────────────────────────────
cat > "$SERVICE" <<EOF
[Unit]
Description=Mirage QUIC Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "systemd service registered"

# ── done ──────────────────────────────────────────────────────────────────────
echo
echo "  ┌─────────────────────────────────────────────┐"
echo "  │  Mirage ${TAG} installed successfully        "
echo "  └─────────────────────────────────────────────┘"
echo
echo "  1. Edit the config file before starting:"
echo "       nano ${CFG}"
echo
echo "  2. Start / stop:"
echo "       systemctl start mirage"
echo "       systemctl stop  mirage"
echo
echo "  3. Enable auto-start on boot:"
echo "       systemctl enable mirage"
echo
echo "  4. Check status and logs:"
echo "       systemctl status mirage"
echo "       journalctl -fu mirage"
echo
