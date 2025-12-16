package main

import (
"log"
"net"
"os"
"os/exec"
"strings"
"time"
	"encoding/hex"

noxcrypto noxcrypto "nox-core/pkg/crypto"
"nox-core/pkg/frame"
"nox-core/pkg/tun"
)

const (
streamData uint32 = 100
)

func main() {
server := getenv("NOX_SERVER", "208.123.185.235:9000")
staticCIDR := getenv("NOX_CLIENT_CIDR", "10.8.0.2/24")
tunName := getenv("NOX_TUN", "nox1")

// ВАРВАРСКИ: ключ временно случайный, т.е. не совместим, поэтому генерим один и тот же через env позже.
// Пока не тормозим: если NOX_KEY_HEX не задан — клиент не будет совпадать с сервером при рестарте,
// поэтому лучше не трогай key до стабилизации. Сейчас делаем как было: общий процесс/перезапуск вместе.
	keyHex := os.Getenv("NOX_KEY_HEX")
	if strings.TrimSpace(keyHex) == "" { log.Fatal("NOX_KEY_HEX required") }
	k, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil { log.Fatal(err) }
	if len(k) != 32 { log.Fatalf("NOX_KEY_HEX must be 32 bytes, got %d", len(k)) }
	ciph, err := noxcrypto.NewCipherFromKey(k)
	if err != nil { log.Fatal(err) }

if err != nil { log.Fatal(err) }

for {
if err := runOnce(server, staticCIDR, tunName, ciph); err != nil {
log.Println("run:", err)
}
time.Sleep(2 * time.Second)
}
}

func runOnce(server, staticCIDR, tunName string, ciph *noxcrypto.Cipher) error {
conn, err := net.DialTimeout("tcp", server, 8*time.Second)
if err != nil {
return err
}
defer conn.Close()

log.Println("connected to server")

t, err := tun.Create(tunName)
if err != nil {
return err
}
log.Println("client TUN", tunName, "created")

assigned := staticCIDR

// ждём control AssignIP
_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
fr, err := frame.Read(conn)
if err == nil && fr.Type == frame.TypeControl && len(fr.Payload) > 1 && fr.Payload[0] == frame.CtrlAssignIP {
assigned = strings.TrimSpace(string(fr.Payload[1:]))
log.Println("Assigned:", assigned)
} else {
log.Println("No assign from server, using static:", assigned)
}
_ = conn.SetReadDeadline(time.Time{})

// применяем IP + route
exec.Command("sh", "-c", "ip addr replace "+assigned+" dev "+tunName).Run()
exec.Command("sh", "-c", "ip link set "+tunName+" up").Run()
exec.Command("sh", "-c", "ip route replace 10.8.0.0/24 dev "+tunName).Run()

// keepalive sender
kaDone := make(chan struct{})
go func() {
tk := time.NewTicker(20 * time.Second)
defer tk.Stop()
for {
select {
case <-tk.C:
_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
_ = frame.Encode(conn, &frame.Frame{
Type: frame.TypeControl, Stream: 0, Flags: 0,
Payload: []byte{frame.CtrlHeartbeat},
})
case <-kaDone:
return
}
}
}()

// conn -> tun
go func() {
for {
_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
fr, err := frame.Read(conn)
if err != nil {
log.Println("read frame:", err)
close(kaDone)
return
}
if fr.Type == frame.TypeControl {
continue
}
pt, err := ciph.Open(fr.Payload)
if err != nil {
log.Println("decrypt:", err)
continue
}
if fr.Stream == streamData {
_, _ = t.WritePacket(pt)
}
}
}()

// tun -> conn
buf := make([]byte, 65535)
for {
n, err := t.ReadPacket(buf)
if err != nil {
close(kaDone)
return err
}
enc := ciph.Seal(buf[:n])
_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
if err := frame.Encode(conn, &frame.Frame{
Type: frame.TypeData, Stream: streamData, Flags: 0, Payload: enc,
}); err != nil {
close(kaDone)
return err
}
}
}

func getenv(k, def string) string {
v := os.Getenv(k)
if v == "" {
return def
}
return v
}
