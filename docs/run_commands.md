# NOX quick test commands (server & client)

## Build and tests (both hosts)
```
go test ./...
go build ./...
mkdir -p bin
go build -o bin/nox-server ./cmd/nox-server
go build -o bin/nox-client ./cmd/nox-client
```

## Clean up old processes/interfaces
```
sudo pkill -f nox-server 2>/dev/null
sudo pkill -f nox-client 2>/dev/null
sudo ip link del nox0 2>/dev/null
sudo ip link del nox1 2>/dev/null
```

## Server launch
```
export NOX_KEY_HEX="<64-hex-key>"
export NOX_LISTEN=":9000"
export NOX_SUBNET="10.8.0.0/24"
export NOX_HANDSHAKE_RPS=20
export NOX_HANDSHAKE_BURST=40
export NOX_MAX_CLIENTS=256
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || \
  sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo env NOX_KEY_HEX="$NOX_KEY_HEX" NOX_LISTEN="$NOX_LISTEN" NOX_SUBNET="$NOX_SUBNET" \
  NOX_HANDSHAKE_RPS="$NOX_HANDSHAKE_RPS" NOX_HANDSHAKE_BURST="$NOX_HANDSHAKE_BURST" \
  NOX_MAX_CLIENTS="$NOX_MAX_CLIENTS" ./bin/nox-server
```

## Client launch
```
export NOX_KEY_HEX="<same-64-hex-key>"
export NOX_SERVER="<server-ip>:9000"
export NOX_CLIENT_CIDR="10.8.0.2/24"
export NOX_TUN="nox1"
export NOX_SESSION_ID="0123456789abcdef"  # optional, keeps sticky IP
sudo env NOX_KEY_HEX="$NOX_KEY_HEX" NOX_SERVER="$NOX_SERVER" NOX_CLIENT_CIDR="$NOX_CLIENT_CIDR" \
  NOX_TUN="$NOX_TUN" NOX_SESSION_ID="$NOX_SESSION_ID" ./bin/nox-client
```

## Connectivity checks (client)
```
ping 10.8.0.1
ping -I nox1 8.8.8.8
```
