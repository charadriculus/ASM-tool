//go:build linux

package dns

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
)

func systemResolvers() ([]string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(io.LimitReader(f, 64<<10))
	out := []string{}
	for s.Scan() {
		fields := strings.Fields(strings.SplitN(s.Text(), "#", 2)[0])
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip, e := netip.ParseAddr(fields[1])
		if e == nil && !ip.IsUnspecified() {
			out = append(out, netip.AddrPortFrom(ip, 53).String())
		}
	}
	if e := s.Err(); e != nil {
		return nil, e
	}
	if len(out) == 0 {
		return nil, errors.New("no system DNS servers in bounded /etc/resolv.conf")
	}
	return out, nil
}
