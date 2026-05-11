//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunPath    = "/dev/net/tun"
	ifNameSize = 16
)

// IFF flags for ioctl
const (
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000 // suppress 4-byte packet info prefix
)

type ifReq struct {
	Name  [ifNameSize]byte
	Flags uint16
	_     [22]byte // padding to fill ifreq struct
}

type Device struct {
	fd   *os.File
	name string
	mtu  int
}

func Open(name string, mtu int) (*Device, error) {
	fd, err := os.OpenFile(tunPath, os.O_RDWR, 0)
	if err != nil {
		
		return nil, fmt.Errorf("open %s: %w (are you root?)", tunPath, err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = IFF_TUN | IFF_NO_PI

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		fd.Fd(),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		fd.Close()
		
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	dev := &Device{fd: fd, name: name, mtu: mtu}
	if err := dev.configure(); err != nil {
		fd.Close()
		
		return nil, err
	}
	
	return dev, nil
}

func (d *Device) configure() error {
	// ip link set <name> up mtu <mtu>
	cmds := [][]string{
		{"ip", "link", "set", d.name, "up"},
		{"ip", "link", "set", d.name, "mtu", fmt.Sprintf("%d", d.mtu)},
	}

	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s: %w", cmd, out, err)
		}
	}
	
	return nil
}

func (d *Device) Read(buf []byte) (int, error)  {
	return d.fd.Read(buf) 
}

func (d *Device) Write(buf []byte) (int, error) { 
	return d.fd.Write(buf) 
}

func (d *Device) Close() error { 
	return d.fd.Close() 
}

func (d *Device) Name() string { 
	return d.name 
}

func (d *Device) MTU() int { 
	return d.mtu 
}

