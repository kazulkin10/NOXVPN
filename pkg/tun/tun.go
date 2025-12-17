package tun

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunDevice = "/dev/net/tun"
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

type Tun struct {
	f *os.File
}

// Create поднимает TUN-интерфейс с именем name в режиме без PI (чистые IP-пакеты).
func Create(name string) (*Tun, error) {
	fd, err := unix.Open(tunDevice, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}

	// ifreq для ioctl(TUNSETIFF)
	var ifr struct {
		Name  [unix.IFNAMSIZ]byte
		Flags uint16
		_     [40 - 2]byte
	}
	copy(ifr.Name[:], []byte(name))
	ifr.Flags = IFF_TUN | IFF_NO_PI

	// прямой SYS_IOCTL с указателем на ifr
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	f := os.NewFile(uintptr(fd), name)
	return &Tun{f: f}, nil
}

// ReadPacket читает один IP-пакет из TUN.
func (t *Tun) ReadPacket(buf []byte) (int, error) {
	return t.f.Read(buf)
}

// WritePacket пишет один IP-пакет в TUN.
func (t *Tun) WritePacket(pkt []byte) (int, error) {
	return t.f.Write(pkt)
}

// Close закрывает TUN.
func (t *Tun) Close() error {
	if t.f == nil {
		return nil
	}
	return t.f.Close()
}

// SetReadDeadline прокидывает дедлайн к файловому дескриптору TUN.
func (t *Tun) SetReadDeadline(ti time.Time) error {
	if t.f == nil {
		return nil
	}
	return t.f.SetDeadline(ti)
}
