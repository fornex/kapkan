//go:build linux

package dataplane

// Attaching the program to an interface, and what xdp_mode actually means.
//
// The three modes are not three ways of doing the same thing. Native (driver)
// XDP runs before an skb is allocated and is roughly an order of magnitude
// faster; generic XDP runs in the stack after allocation, works on any device,
// and is the only option on some virtual NICs. Which one an operator gets
// changes the capacity of the box, so "auto" must RECORD what it chose rather
// than quietly settling.

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/kapkan-io/kapkan/internal/config"
)

// resolveInterface looks up an interface's current index, distinguishing "no
// such interface" from a lookup failure. A missing interface is an expected,
// recoverable state (a NIC that has not appeared yet, a veth being recreated);
// anything else is not.
func resolveInterface(name string) (index int, exists bool, err error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		// net does not export a sentinel for this, and the underlying error is
		// a *net.OpError wrapping ENODEV on Linux. Treat any lookup failure for
		// a syntactically valid name as "not present": the watcher retries, and
		// the alternative is refusing to start because a NIC is down.
		return 0, false, nil
	}
	return ifi.Index, true, nil
}

// xdpFlagsFor maps a mode to the kernel's attach flag.
func xdpFlagsFor(mode string) link.XDPAttachFlags {
	if mode == config.XDPModeNative {
		return link.XDPDriverMode
	}
	return link.XDPGenericMode
}

// attachXDP attaches prog to an interface, honouring the configured mode, and
// returns the mode that is actually in force.
//
//   - native: driver mode, and a failure is returned. An operator who wrote
//     native asked to be told when the driver cannot do it, because the whole
//     reason to write it is to refuse the ten-times-slower path silently.
//   - generic: skb mode, forced. Useful on virtio and required for some
//     tunnel devices.
//   - auto: driver mode, falling back to skb when the driver has no XDP support
//     at all. The fallback is recorded as a condition, not swallowed.
func attachXDP(prog *ebpf.Program, iface string, index int, mode string) (link.Link, string, error) {
	try := func(m string) (link.Link, error) {
		return link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: index,
			Flags:     xdpFlagsFor(m),
		})
	}

	switch mode {
	case config.XDPModeGeneric:
		l, err := try(config.XDPModeGeneric)
		if err != nil {
			return nil, "", attachError(iface, index, config.XDPModeGeneric, err)
		}
		return l, config.XDPModeGeneric, nil

	case config.XDPModeNative:
		l, err := try(config.XDPModeNative)
		if err != nil {
			return nil, "", attachError(iface, index, config.XDPModeNative, err)
		}
		return l, config.XDPModeNative, nil

	default: // auto
		l, err := try(config.XDPModeNative)
		if err == nil {
			return l, config.XDPModeNative, nil
		}
		if !unsupportedMode(err) {
			// EBUSY, EEXIST, EPERM: the hook is taken or we are not allowed to
			// touch it. Generic mode would fail for the same reason, and trying
			// it would only replace a precise error with a vaguer one.
			return nil, "", attachError(iface, index, config.XDPModeNative, err)
		}
		g, gerr := try(config.XDPModeGeneric)
		if gerr != nil {
			return nil, "", fmt.Errorf("%w (native was refused with: %v)",
				attachError(iface, index, config.XDPModeGeneric, gerr), err)
		}
		return g, config.XDPModeGeneric, nil
	}
}

// unsupportedMode reports whether an attach failure means "this driver has no
// native XDP", as opposed to "you may not attach here" or "something else
// already has".
//
// EOPNOTSUPP is what a device with no ndo_bpf returns. EINVAL is included
// because several drivers reject XDP_SETUP_PROG that way (an MTU above the
// driver's XDP limit, or an unsupported queue configuration), and in every such
// case the generic path is the right answer. EBUSY/EEXIST are deliberately
// excluded: falling back then would mean stacking a generic program under
// something else's native one, or reporting success for an attach that did not
// replace what is really filtering the traffic.
func unsupportedMode(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL)
}

// attachError wraps an attach failure with the diagnosis an operator needs. The
// two cases worth naming are the ones whose kernel errno says nothing useful.
func attachError(iface string, index int, mode string, err error) error {
	msg := fmt.Sprintf("dataplane: attach XDP to %s (ifindex %d) in %s mode: %v", iface, index, mode, err)
	switch {
	case errors.Is(err, syscall.EBUSY), errors.Is(err, syscall.EEXIST):
		return fmt.Errorf("%s — another XDP program already owns this interface's hook. "+
			"Check with `ip -details link show %s` (or `bpftool net`) and remove it; "+
			"two XDP programs cannot share a device", msg, iface)
	case errors.Is(err, syscall.EOPNOTSUPP) && mode == config.XDPModeNative:
		return fmt.Errorf("%s — this driver has no native XDP support. "+
			"Use dataplane.xdp_mode: auto to fall back to the generic (skb) path, "+
			"or generic to force it; native costs roughly an order of magnitude less CPU "+
			"per packet, which is why asking for it fails rather than degrades", msg)
	case errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%s — attaching needs CAP_NET_ADMIN; see "+
			"engine/deploy/dataplane-operations.md §1", msg)
	}
	return errors.New(msg)
}
