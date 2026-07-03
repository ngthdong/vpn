//go:build linux

package tun

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
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
	FD      *os.File
	name    string
	address string
	mtu     int
}

func Open(name string, address string, mtu int) (*Device, error) {
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

	dev := &Device{
		FD:      fd,
		name:    name,
		address: address,
		mtu:     mtu,
	}
	if err := dev.configure(); err != nil {
		fd.Close()
		return nil, err
	}

	return dev, nil
}

func (d *Device) configure() error {
	link, err := netlink.LinkByName(d.name)
	if err != nil {
		return fmt.Errorf("get link %q: %w", d.name, err)
	}

	addr, err := netlink.ParseAddr(d.address)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", d.address, err)
	}

	// Replace avoids "file exists" when restarting.
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("assign ip %q: %w", d.address, err)
	}

	if err := netlink.LinkSetMTU(link, d.mtu); err != nil {
		return fmt.Errorf("set mtu %d: %w", d.mtu, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring link up: %w", err)
	}

	return nil
}

func (d *Device) Read(buf []byte) (int, error) {
	return unix.Read(int(d.FD.Fd()), buf)
}

func (d *Device) Write(buf []byte) (int, error) {
	return unix.Write(int(d.FD.Fd()), buf)
}

func (d *Device) Close() error {
	return d.FD.Close()
}

func (d *Device) Name() string {
	return d.name
}

func (d *Device) MTU() int {
	return d.mtu
}
