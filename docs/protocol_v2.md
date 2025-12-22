# NOX v2 Protocol Specification

## Goals
- TUN-based L3 VPN (IPv4 first, IPv6 later)
- Server authoritative for addressing, routes, MTU
- Explicit control plane separated from data plane
- Deterministic handshake and session lifecycle

## Versioning
- `Version` is a single byte. Current value: `0x02`.
- All control frames carry the negotiated version.
- If the server cannot serve the requested version, it replies with `CtrlError` and closes the connection.

## Capability Flags
- `0x0001` – IPv6-in-tunnel
- `0x0002` – Rekey supported
- `0x0004` – MTU negotiation supported
- `0x0008` – QUIC transport supported (future)
- `0x0010` – Replay protection required

## Frame Envelope
```
+------------+-----------+----------------+----------------+----------------+
| Version(1) | Kind(1)   | Reserved(2)    | Length(2)      | Payload(Length) |
+------------+-----------+----------------+----------------+----------------+
```
- `Kind`: 0x01 Control, 0x02 Data.
- Payload is control-specific TLV or raw data. Length excludes the 6-byte header.
- Transport framing is length-delimited; each encrypted record is prefixed with its ciphertext length (uint16).

## Control Opcodes
- `0x01 HELLO`
- `0x02 ASSIGN_IP`
- `0x03 ROUTES`
- `0x04 HEARTBEAT`
- `0x05 REKEY`
- `0x06 CLOSE`
- `0x07 ERROR` (version/capability mismatch, auth failure)

### HELLO (client → server)
Fields:
- Version (1 byte)
- Capabilities (2 bytes bitmask)
- SessionID (8 bytes)
- ClientNonce (16 bytes random)
- DesiredMTU (uint16), 0 = default

### ASSIGN_IP (server → client)
- SessionID (8 bytes)
- AssignedIPv4 (4 bytes)
- PrefixLen (1 byte)
- MTU (uint16, negotiated; min(desired, server))
- ServerNonce (16 bytes)

### ROUTES (server → client)
- Count (1 byte), then repeated routes:
  - IPv4 network (4 bytes) + PrefixLen (1 byte)
- Optional DNS addresses as TLV (future extension)

### HEARTBEAT (bidirectional)
- Echo counter (uint32) for liveness and RTT measurement.

### REKEY (server → client)
- Epoch (uint32)
- RekeyNonce (16 bytes)
- New capabilities (optional, same layout as HELLO)

### CLOSE (bidirectional)
- ReasonCode (uint16)
- Text (utf-8, length-prefixed uint8)

### ERROR (server → client)
- ReasonCode (uint16): unsupported version, auth failure, rate-limit, etc.

## Data Frames
- `Kind=0x02`
- Contains encrypted payload (raw IP packet) with monotonically increasing `Seq` in AEAD nonce.
- Replay protection uses a sliding window (default 64).

## Handshake FSM (high level)
Client states: `Init → HelloSent → AssignRecv → RoutesRecv? → Ready → Rekeying? → Closing`.
Server states: `Init → HelloRecv → AssignSent → RoutesSent? → Ready → Rekeying? → Closing`.

Rules:
- No data frames before `Ready` on both sides.
- Session keys derived via HKDF(master, SessionID || ClientNonce || ServerNonce).
- Rekey changes epoch; both sides swap keys without dropping the session.
- HEARTBEAT allowed only in Ready/Rekeying.

## MTU Negotiation
- Client proposes DesiredMTU in HELLO.
- Server responds with MTU = clamp(1200..server_max, DesiredMTU if non-zero else server_max).
- Both sides must respect negotiated MTU for TUN and fragmentation policy.

## Replay Protection
- AEAD nonce includes `(epoch, seq)`; seq starts at 0 after handshake or rekey.
- Receiver tracks highest seq and a 64-packet window; duplicates are dropped.

## TUN Lifecycle
- Server configures `nox0`: up, gateway IP = first host of subnet, route for the subnet.
- Client configures its TUN only after ASSIGN_IP; route for assigned subnet is added.
- TUN teardown happens on session close.

## Transport
- Default: TCP. Future: QUIC via capability flag.
- Transport abstraction separates connection accept/dial from protocol logic.

## Security Model
- ChaCha20-Poly1305 AEAD.
- Master key from `NOX_KEY_HEX` (32 bytes).
- Per-session keys via HKDF; Rekey uses REKEY nonce and epoch.
- Reject any encrypted record before handshake completion.

## Migration Notes
- v2 is not backward compatible with v1.
- v1 binaries remain unchanged; v2 binaries live under new commands.
