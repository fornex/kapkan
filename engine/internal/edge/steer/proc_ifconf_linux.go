//go:build linux

package steer

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// procIfconf is the kernel's struct ifconf: the buffer's length, which the
// kernel sets to what it wrote, and the buffer. Go lays an int32 followed by
// a pointer out as C does, on 32- and on 64-bit kernels.
type procIfconf struct {
	len int32
	buf unsafe.Pointer
}

// procIfreqSize is sizeof(struct ifreq): the IFNAMSIZ name, then a union
// whose largest member is struct ifmap — two unsigned longs and five bytes,
// padded to eight: 40 bytes on a 64-bit kernel, 32 on a 32-bit one. The
// address of an SIOCGIFCONF entry is a sockaddr_in right after the name: the
// family at offset 16, the port at 18, the address at 20.
const procIfreqSize = 16 + 2*int(unsafe.Sizeof(uintptr(0))) + 8

// procIfaddrs4 lists the IPv4 addresses of this box's interfaces with
// SIOCGIFCONF on an AF_INET datagram socket: an ioctl, not netlink, so it
// needs no family the unit does not grant (I1), and nothing outside the
// standard library (I4). The kernel fills the list under the RTNL lock — one
// consistent view of every address, secondaries included — in microseconds,
// however large the routing table. A list that filled its buffer may have
// been cut short, so it is read again into one twice the size.
func procIfaddrs4() ([]netip.Addr, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	// A nil buffer asks for the length the list needs.
	var ifc procIfconf
	if err := procIoctlIfconf(fd, &ifc); err != nil {
		return nil, err
	}
	size := int(ifc.len) + 8*procIfreqSize
	for range 8 {
		buf := make([]byte, size)
		ifc = procIfconf{len: int32(len(buf)), buf: unsafe.Pointer(&buf[0])}
		if err := procIoctlIfconf(fd, &ifc); err != nil {
			return nil, err
		}
		if n := int(ifc.len); n >= 0 && n <= len(buf)-procIfreqSize {
			return procIfreqAddrs(buf[:n]), nil
		}
		size *= 2
	}
	return nil, errors.New("SIOCGIFCONF: the address list kept growing while it was read")
}

func procIoctlIfconf(fd int, ifc *procIfconf) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFCONF, uintptr(unsafe.Pointer(ifc)))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCGIFCONF", errno)
	}
	return nil
}

// procIfreqAddrs reads the IPv4 addresses out of SIOCGIFCONF's entries.
func procIfreqAddrs(b []byte) []netip.Addr {
	var addrs []netip.Addr
	for ; len(b) >= procIfreqSize; b = b[procIfreqSize:] {
		if binary.NativeEndian.Uint16(b[16:]) == syscall.AF_INET {
			addrs = append(addrs, netip.AddrFrom4([4]byte(b[20:24])))
		}
	}
	return addrs
}
