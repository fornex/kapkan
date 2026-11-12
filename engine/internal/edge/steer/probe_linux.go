//go:build linux

package steer

import (
	"os"
	"syscall"
)

// probeFreebind sets IP_FREEBIND on an IPv6 socket of the Prober, before its
// bind. IPv6 bind() takes only an address assigned to an interface
// (ipv6_chk_addr), and a VIP the kernel delivers locally through an AnyIP
// route (`ip -6 route add local P dev lo`) is on none: without the option,
// such a VIP could never be the probe's source, and every probe of it would
// be blind while it serves. IPv4 bind() already takes any address of the
// local table, AnyIP ranges included, so an IPv4 socket is left as it is, and
// its bind still refuses an address the kernel dropped. SOL_IP/IP_FREEBIND
// works on an AF_INET6 socket (ipv6_setsockopt hands SOL_IP to
// ip_setsockopt), on any kernel; IPV6_FREEBIND would need 4.15. It needs no
// capability. Its failure is the Prober's own, so the attempt is blind.
func probeFreebind(network string, c syscall.RawConn) error {
	if network != "tcp6" {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1)
	}); err != nil {
		return err
	}
	if serr != nil {
		return os.NewSyscallError("setsockopt", serr)
	}
	return nil
}
