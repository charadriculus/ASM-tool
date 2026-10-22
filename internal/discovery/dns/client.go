package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type Record struct {
	Name, Type, Value string
	TTL               uint32
}
type Answer struct {
	Name     string
	Type     uint16
	RCode    uint16
	Resolver string
	Records  []Record
	Negative bool
}
type Client struct {
	Resolvers        []string
	Timeout          time.Duration
	AttemptTimeout   time.Duration
	QueriesPerSecond float64
	mu               sync.Mutex
	last             time.Time
}

func NewClient(resolvers []string, timeout time.Duration) (*Client, error) {
	return NewClientWithRate(resolvers, timeout, 4)
}

func NewClientWithRate(resolvers []string, timeout time.Duration, qps float64) (*Client, error) {
	if timeout <= 0 || qps <= 0 || math.IsNaN(qps) || math.IsInf(qps, 0) {
		return nil, errors.New("DNS timeout and rate must be positive finite values")
	}
	ordered := make([]string, 0, len(resolvers))
	seen := map[string]bool{}
	for _, r := range resolvers {
		host, port, e := net.SplitHostPort(r)
		if e != nil {
			host = r
			port = "53"
		}
		ip, e := netip.ParseAddr(strings.Trim(host, "[]"))
		portNum, portErr := strconv.Atoi(port)
		if e != nil || portErr != nil || portNum < 1 || portNum > 65535 || ip.Is6() && ip.IsLinkLocalUnicast() && ip.Zone() == "" {
			return nil, fmt.Errorf("invalid DNS resolver %q", r)
		}
		endpoint := net.JoinHostPort(ip.String(), port)
		if !seen[endpoint] {
			seen[endpoint] = true
			ordered = append(ordered, endpoint)
		}
	}
	if len(ordered) == 0 {
		return nil, errors.New("no valid DNS resolver")
	}
	attempt := min(timeout, 1500*time.Millisecond)
	return &Client{Resolvers: ordered, Timeout: min(timeout, 2500*time.Millisecond), AttemptTimeout: attempt, QueriesPerSecond: qps}, nil
}

// NewSystemClient adds the public fallback only after discovering system resolvers.
func NewSystemClient(timeout time.Duration) (*Client, error) {
	return NewSystemClientWithRate(timeout, 4)
}
func NewSystemClientWithRate(timeout time.Duration, qps float64) (*Client, error) {
	resolvers, err := systemResolvers()
	if err != nil {
		resolvers = nil
	}
	return NewClientWithRate(append(resolvers, "1.1.1.1:53", "1.0.0.1:53"), timeout, qps)
}

func (c *Client) wait(ctx context.Context) error {
	seconds := 1.01 / c.QueriesPerSecond
	interval := time.Duration(math.MaxInt64)
	if seconds < float64(math.MaxInt64)/float64(time.Second) {
		interval = time.Duration(seconds * float64(time.Second))
		if interval < time.Nanosecond {
			interval = time.Nanosecond
		}
	}
	for {
		c.mu.Lock()
		d := time.Until(c.last.Add(interval))
		if d <= 0 {
			c.last = time.Now()
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (c *Client) Query(ctx context.Context, rawName string, typ uint16) (Answer, error) {
	name := strings.TrimSuffix(foldDNSNameASCII(rawName), ".")
	if name == "" || len(name) > 253 || !isASCII(name) {
		return Answer{}, errors.New("invalid DNS name; use canonical ASCII form")
	}
	qname, e := dnsmessage.NewName(name + ".")
	if e != nil {
		return Answer{}, e
	}
	qtype := dnsmessage.Type(typ)
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA && qtype != dnsmessage.TypeCNAME && qtype != dnsmessage.TypeMX && qtype != dnsmessage.TypeNS && qtype != dnsmessage.TypeSOA && qtype != dnsmessage.TypePTR && qtype != dnsmessage.TypeTXT {
		return Answer{}, fmt.Errorf("unsupported DNS query type %d", typ)
	}
	var idb [2]byte
	if _, e = rand.Read(idb[:]); e != nil {
		return Answer{}, e
	}
	id := binary.BigEndian.Uint16(idb[:])
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}}}
	packet, e := msg.Pack()
	if e != nil {
		return Answer{}, e
	}
	var errs []error
	var lastAnswer Answer
	var lastErr error
	for _, resolver := range c.Resolvers {
		if e = c.wait(ctx); e != nil {
			return Answer{}, e
		}
		contactCtx, cancel := context.WithTimeout(ctx, c.Timeout)
		response, tcpFallback, err := c.exchange(contactCtx, resolver, packet, id, qname, qtype)
		err = contactError(contactCtx, err)
		cancel()
		if err == nil && tcpFallback {
			if err = c.wait(ctx); err == nil {
				contactCtx, cancel = context.WithTimeout(ctx, c.Timeout)
				response, err = c.exchangeTCP(contactCtx, resolver, packet)
				err = contactError(contactCtx, err)
				cancel()
			}
		}
		if err != nil {
			lastErr = fmt.Errorf("resolver %s: %w", resolver, err)
			errs = append(errs, lastErr)
			continue
		}
		answer, err := decodeRelevant(response, id, qname, qtype, resolver)
		if err != nil {
			lastErr = fmt.Errorf("resolver %s: %w", resolver, err)
			errs = append(errs, lastErr)
			continue
		}
		if answer.RCode == uint16(dnsmessage.RCodeNameError) {
			answer.Negative = true
			return answer, nil
		}
		if answer.RCode != uint16(dnsmessage.RCodeSuccess) {
			lastAnswer = answer
			lastErr = nil
			continue
		}
		return answer, nil
	}
	if err := ctx.Err(); err != nil {
		return Answer{}, err
	}
	if lastErr != nil {
		return Answer{}, lastErr
	}
	if lastAnswer.Resolver != "" {
		return lastAnswer, nil
	}
	return Answer{}, errors.Join(errs...)
}

func contactError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return context.DeadlineExceeded
		}
	}
	return err
}

func (c *Client) exchange(ctx context.Context, resolver string, packet []byte, id uint16, q dnsmessage.Name, typ dnsmessage.Type) ([]byte, bool, error) {
	deadline := time.Now().Add(c.AttemptTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if !deadline.After(time.Now()) {
		return nil, false, context.DeadlineExceeded
	}
	dialer := net.Dialer{Timeout: c.AttemptTimeout}
	conn, e := dialer.DialContext(ctx, "udp", resolver)
	if e != nil {
		return nil, false, e
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, e = conn.Write(packet); e != nil {
		conn.Close()
		return nil, false, e
	}
	buf := make([]byte, 4096)
	n, e := conn.Read(buf)
	conn.Close()
	if e != nil {
		return nil, false, e
	}
	buf = buf[:n]
	var m dnsmessage.Message
	if e = m.Unpack(buf); e != nil {
		return nil, false, e
	}
	if err := validateQuestion(m, id, q, typ); err != nil {
		return nil, false, err
	}
	if m.Header.Truncated {
		return nil, true, nil
	}
	return buf, false, nil
}
func (c *Client) exchangeTCP(ctx context.Context, resolver string, packet []byte) ([]byte, error) {
	deadline := time.Now().Add(c.AttemptTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if !deadline.After(time.Now()) {
		return nil, context.DeadlineExceeded
	}
	conn, e := (&net.Dialer{Timeout: c.AttemptTimeout}).DialContext(ctx, "tcp", resolver)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(deadline)
	if len(packet) > 65535 {
		return nil, errors.New("DNS query too large")
	}
	frame := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	copy(frame[2:], packet)
	if _, e = conn.Write(frame); e != nil {
		return nil, e
	}
	var header [2]byte
	if _, e = io.ReadFull(conn, header[:]); e != nil {
		return nil, e
	}
	size := binary.BigEndian.Uint16(header[:])
	if size < 12 || size > 4096 {
		return nil, errors.New("invalid DNS TCP response length")
	}
	buf := make([]byte, int(size))
	if _, e = io.ReadFull(conn, buf); e != nil {
		return nil, e
	}
	return buf, nil
}
func validateQuestion(m dnsmessage.Message, id uint16, q dnsmessage.Name, typ dnsmessage.Type) error {
	if m.Header.ID != id || !m.Header.Response || m.Header.OpCode != 0 || len(m.Questions) != 1 || !equalDNSNameASCII(m.Questions[0].Name.String(), q.String()) || m.Questions[0].Class != dnsmessage.ClassINET || m.Questions[0].Type != typ {
		return errors.New("DNS response does not match request")
	}
	return nil
}

func equalDNSNameASCII(a, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func foldDNSNameASCII(name string) string {
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func decodeRelevant(buf []byte, id uint16, q dnsmessage.Name, typ dnsmessage.Type, resolver string) (Answer, error) {
	var m dnsmessage.Message
	if e := m.Unpack(buf); e != nil {
		return Answer{}, e
	}
	if err := validateQuestion(m, id, q, typ); err != nil {
		return Answer{}, err
	}
	if m.Header.Truncated {
		return Answer{}, errors.New("truncated DNS response after TCP fallback")
	}
	if err := validateASCIIAnswerNames(m); err != nil {
		return Answer{}, err
	}
	out := Answer{Name: strings.TrimSuffix(foldDNSNameASCII(q.String()), "."), Type: uint16(typ), RCode: uint16(m.Header.RCode), Resolver: resolver}
	aliases := map[string]string{}
	for _, rr := range m.Answers {
		if rr.Header.Class != dnsmessage.ClassINET || rr.Header.Type != dnsmessage.TypeCNAME {
			continue
		}
		if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
			aliases[strings.TrimSuffix(foldDNSNameASCII(rr.Header.Name.String()), ".")] = strings.TrimSuffix(foldDNSNameASCII(cname.CNAME.String()), ".")
		}
	}
	terminal := out.Name
	if typ != dnsmessage.TypeCNAME {
		visited := map[string]bool{}
		for hops := 0; ; hops++ {
			if visited[terminal] {
				return Answer{}, errors.New("DNS CNAME cycle")
			}
			visited[terminal] = true
			next, ok := aliases[terminal]
			if !ok {
				break
			}
			if hops >= 8 {
				return Answer{}, errors.New("DNS CNAME chain exceeds 8 hops")
			}
			terminal = next
		}
	}
	for _, rr := range m.Answers {
		if rr.Header.Class != dnsmessage.ClassINET {
			continue
		}
		owner := strings.TrimSuffix(foldDNSNameASCII(rr.Header.Name.String()), ".")
		kind := ""
		value := ""
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			kind = "A"
			value = netip.AddrFrom4(body.A).String()
		case *dnsmessage.AAAAResource:
			kind = "AAAA"
			value = netip.AddrFrom16(body.AAAA).String()
		case *dnsmessage.CNAMEResource:
			kind = "CNAME"
			value = strings.TrimSuffix(foldDNSNameASCII(body.CNAME.String()), ".")
		case *dnsmessage.MXResource:
			kind = "MX"
			value = fmt.Sprintf("%d %s", body.Pref, strings.TrimSuffix(foldDNSNameASCII(body.MX.String()), "."))
		case *dnsmessage.NSResource:
			kind = "NS"
			value = strings.TrimSuffix(foldDNSNameASCII(body.NS.String()), ".")
		case *dnsmessage.SOAResource:
			kind = "SOA"
			value = fmt.Sprintf("%s %s %d %d %d %d %d", body.NS.String(), body.MBox.String(), body.Serial, body.Refresh, body.Retry, body.Expire, body.MinTTL)
		case *dnsmessage.PTRResource:
			kind = "PTR"
			value = strings.TrimSuffix(foldDNSNameASCII(body.PTR.String()), ".")
		case *dnsmessage.TXTResource:
			kind = "TXT"
			value = formatTXT(body.TXT)
		}
		if kind == "" {
			continue
		}
		if kind == "CNAME" {
			if typ != dnsmessage.TypeCNAME || owner != out.Name {
				continue
			}
			out.Records = append(out.Records, Record{out.Name, kind, value, rr.Header.TTL})
			continue
		}
		if owner != terminal {
			continue
		}
		if (typ == dnsmessage.TypeA && kind == "A") || (typ == dnsmessage.TypeAAAA && kind == "AAAA") || typ == dnsmessage.TypeMX && kind == "MX" || typ == dnsmessage.TypeNS && kind == "NS" || typ == dnsmessage.TypeSOA && kind == "SOA" || typ == dnsmessage.TypePTR && kind == "PTR" || typ == dnsmessage.TypeTXT && kind == "TXT" {
			out.Records = append(out.Records, Record{out.Name, kind, value, rr.Header.TTL})
		}
	}
	return out, nil
}

func validateASCIIAnswerNames(m dnsmessage.Message) error {
	for _, rr := range m.Answers {
		if !isASCII(rr.Header.Name.String()) {
			return errors.New("non-ASCII DNS answer owner")
		}
		valid := func(name dnsmessage.Name) bool { return isASCII(name.String()) }
		switch body := rr.Body.(type) {
		case *dnsmessage.CNAMEResource:
			if !valid(body.CNAME) {
				return errors.New("non-ASCII DNS CNAME target")
			}
		case *dnsmessage.MXResource:
			if !valid(body.MX) {
				return errors.New("non-ASCII DNS MX target")
			}
		case *dnsmessage.NSResource:
			if !valid(body.NS) {
				return errors.New("non-ASCII DNS NS target")
			}
		case *dnsmessage.PTRResource:
			if !valid(body.PTR) {
				return errors.New("non-ASCII DNS PTR target")
			}
		case *dnsmessage.SOAResource:
			if !valid(body.NS) || !valid(body.MBox) {
				return errors.New("non-ASCII DNS SOA name")
			}
		}
	}
	return nil
}

func formatTXT(segments []string) string {
	var out strings.Builder
	for i, segment := range segments {
		if i > 0 {
			out.WriteByte(' ')
		}
		out.WriteByte('"')
		for j := 0; j < len(segment); j++ {
			b := segment[j]
			switch {
			case b == '"' || b == '\\':
				out.WriteByte('\\')
				out.WriteByte(b)
			case b >= 0x20 && b <= 0x7e:
				out.WriteByte(b)
			default:
				fmt.Fprintf(&out, "\\%03d", b)
			}
		}
		out.WriteByte('"')
	}
	return out.String()
}
