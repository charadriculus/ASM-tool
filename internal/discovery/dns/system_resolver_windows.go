//go:build windows

package dns

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemResolvers() ([]string, error) {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, nil, &size)
	if err != syscall.ERROR_BUFFER_OVERFLOW || size == 0 || size > 1<<20 {
		return nil, errors.New("cannot size Windows DNS adapter list")
	}
	buf := make([]byte, size)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []string{}
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for dns := adapter.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}
			addr, e := netip.ParseAddr(ip.String())
			if e != nil || addr.IsUnspecified() {
				continue
			}
			if addr.Is6() && addr.IsLinkLocalUnicast() {
				zone := uint32(0)
				if dns.Address.SockaddrLength >= int32(unsafe.Sizeof(windows.RawSockaddrInet6{})) {
					raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(dns.Address.Sockaddr))
					zone = raw.Scope_id
				}
				if zone == 0 {
					zone = adapter.Ipv6IfIndex
				}
				if zone == 0 {
					continue
				}
				addr = addr.WithZone(strconv.FormatUint(uint64(zone), 10))
			}
			endpoint := net.JoinHostPort(addr.String(), "53")
			if !seen[endpoint] {
				seen[endpoint] = true
				out = append(out, endpoint)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("Windows has no DNS servers on active adapters")
	}
	return out, nil
}
