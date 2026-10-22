package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func localDNSServer(t *testing.T, handler func(dnsmessage.Message) dnsmessage.Message) string {
	t.Helper()
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			response := handler(q)
			raw, e := response.Pack()
			if e == nil {
				_, _ = pc.WriteTo(raw, addr)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func localDNSTransports(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for attempt := 0; attempt < 8; attempt++ {
		udp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcp, err := net.Listen("tcp", udp.LocalAddr().String())
		if err == nil {
			return udp, tcp
		}
		_ = udp.Close()
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	t.Fatal("could not reserve matching local UDP/TCP DNS endpoints after address-in-use collisions")
	return nil, nil
}

func TestQueryFollowsOnlyRequestedCNAMEAnswerAndPreservesTTL(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		alias, _ := dnsmessage.NewName("edge.example.test.")
		terminal, _ := dnsmessage.NewName("origin.example.test.")
		unrelated, _ := dnsmessage.NewName("noise.example.test.")
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 70}, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
			{Header: dnsmessage.ResourceHeader{Name: alias, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: terminal}},
			{Header: dnsmessage.ResourceHeader{Name: terminal, Class: dnsmessage.ClassINET, TTL: 55}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 8}}},
			{Header: dnsmessage.ResourceHeader{Name: unrelated, Class: dnsmessage.ClassINET, TTL: 99}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}}},
		}}
	})
	c, _ := NewClient([]string{resolver}, 3*time.Second)
	if len(c.Resolvers) != 1 || c.Resolvers[0] != resolver {
		t.Fatalf("explicit fixture resolver chain changed: %v", c.Resolvers)
	}
	a, e := c.Query(context.Background(), "www.example.test", uint16(dnsmessage.TypeA))
	if e != nil {
		t.Fatal(e)
	}
	if len(a.Records) != 1 || a.Records[0].Type != "A" || a.Records[0].Name != "www.example.test" || a.Records[0].Value != "192.0.2.8" || a.Records[0].TTL != 55 {
		t.Fatalf("unexpected relevant answers: %+v", a.Records)
	}
	for _, r := range a.Records {
		if strings.Contains(r.Value, "203.0.113.9") {
			t.Fatalf("unrelated address accepted: %+v", a.Records)
		}
	}
}

func TestQueryRejectsMismatchedQuestion(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		wrong, _ := dnsmessage.NewName("other.example.test.")
		q.Header.Response = true
		q.Questions[0].Name = wrong
		return q
	})
	c, _ := NewClient([]string{resolver}, 3*time.Second)
	if len(c.Resolvers) != 1 || c.Resolvers[0] != resolver {
		t.Fatalf("explicit fixture resolver chain changed: %v", c.Resolvers)
	}
	if _, e := c.Query(context.Background(), "www.example.test", uint16(dnsmessage.TypeA)); e == nil || !strings.Contains(e.Error(), "does not match") {
		t.Fatalf("mismatched question accepted, err=%v", e)
	}
}

func TestQueryQuestionComparisonIsDNSCaseInsensitive(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		upper, _ := dnsmessage.NewName(strings.ToUpper(q.Questions[0].Name.String()))
		q.Header.Response = true
		q.Questions[0].Name = upper
		return q
	})
	c, err := NewClient([]string{resolver}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query(context.Background(), "www.example.test", uint16(dnsmessage.TypeA)); err != nil {
		t.Fatalf("case-only question mismatch rejected: %v", err)
	}
}

func TestQueryRejectsUnicodeDNSCaseFoldBeforeTCFallback(t *testing.T) {
	udp, tcp := localDNSTransports(t)
	defer udp.Close()
	defer tcp.Close()
	go func() {
		buf := make([]byte, 4096)
		n, addr, readErr := udp.ReadFrom(buf)
		if readErr != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil {
			return
		}
		lookalike, nameErr := dnsmessage.NewName("K.example.test.")
		if nameErr != nil {
			return
		}
		q.Header.Response = true
		q.Header.Truncated = true
		q.Questions[0].Name = lookalike
		raw, packErr := q.Pack()
		if packErr == nil {
			_, _ = udp.WriteTo(raw, addr)
		}
	}()
	c, err := NewClient([]string{udp.LocalAddr().String()}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Query(context.Background(), "k.example.test", uint16(dnsmessage.TypeA)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Unicode lookalike question accepted: %v", err)
	}
	if err = tcp.(*net.TCPListener).SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := tcp.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("mismatched truncated response triggered TCP fallback")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("unexpected TCP listener result: %v", err)
	}
}

func TestDNSASCIINameComparisonDoesNotFoldUTF8Bytes(t *testing.T) {
	if !equalDNSNameASCII("Example.COM.", "example.com") {
		t.Fatal("ASCII DNS case variation did not compare equal")
	}
	if equalDNSNameASCII("é.test.", "ê.test.") {
		t.Fatal("distinct UTF-8 DNS names compared equal")
	}
}

func TestQueryRejectsNonASCIIAnswerOwnerAndCNAMEAlias(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  dnsmessage.Type
	}{
		{name: "owner", typ: dnsmessage.TypeA},
		{name: "alias", typ: dnsmessage.TypeCNAME},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
				kelvin, _ := dnsmessage.NewName("K.example.test.")
				owner := q.Questions[0].Name
				var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 77}}
				if tc.name == "owner" {
					owner = kelvin
				} else {
					body = &dnsmessage.CNAMEResource{CNAME: kelvin}
				}
				return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{
					{Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 30}, Body: body},
				}}
			})
			c, err := NewClient([]string{resolver}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Query(context.Background(), "k.example.test", uint16(tc.typ)); err == nil || !strings.Contains(err.Error(), "non-ASCII DNS") {
				t.Fatalf("non-ASCII wire name escaped validation: %v", err)
			}
		})
	}
}

func TestCNAMEQueryReturnsOnlyQueriedOwnerRRset(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		root, _ := dnsmessage.NewName("root.example.test.")
		z, _ := dnsmessage.NewName("z.example.test.")
		a, _ := dnsmessage.NewName("a.example.test.")
		terminal, _ := dnsmessage.NewName("terminal.example.test.")
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: root, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: z}},
			{Header: dnsmessage.ResourceHeader{Name: z, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: a}},
			{Header: dnsmessage.ResourceHeader{Name: a, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: terminal}},
		}}
	})
	c, err := NewClient([]string{resolver}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Query(context.Background(), "root.example.test", uint16(dnsmessage.TypeCNAME))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 1 || got.Records[0].Name != "root.example.test" || got.Records[0].Value != "z.example.test" {
		t.Fatalf("CNAME query did not preserve owner RRset: %+v", got.Records)
	}
}

func TestQueryRejectsCNAMECycleAndOverlongChainWithIntermediateAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain int
		want  string
	}{
		{name: "cycle", chain: 2, want: "DNS CNAME cycle"},
		{name: "depth", chain: 9, want: "exceeds 8 hops"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
				root := strings.TrimSuffix(q.Questions[0].Name.String(), ".")
				answers := make([]dnsmessage.Resource, 0, tc.chain+1)
				owner := root
				for i := 0; i < tc.chain; i++ {
					next := "node" + string(rune('a'+i)) + ".example.test"
					if tc.name == "cycle" && i == tc.chain-1 {
						next = root
					}
					ownerName, _ := dnsmessage.NewName(owner + ".")
					nextName, _ := dnsmessage.NewName(next + ".")
					answers = append(answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: ownerName, Class: dnsmessage.ClassINET, TTL: 30},
						Body:   &dnsmessage.CNAMEResource{CNAME: nextName},
					})
					owner = next
					if i == 0 {
						answers = append(answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: nextName, Class: dnsmessage.ClassINET, TTL: 30},
							Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 44}},
						})
					}
				}
				return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions, Answers: answers}
			})
			c, err := NewClient([]string{resolver}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := c.Query(context.Background(), "root.example.test", uint16(dnsmessage.TypeA)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed CNAME graph accepted, records=%+v err=%v", got.Records, err)
			}
		})
	}
}

func TestQueryTCFallsBackToTCP(t *testing.T) {
	udp, tcp := localDNSTransports(t)
	defer udp.Close()
	defer tcp.Close()
	go func() {
		b := make([]byte, 4096)
		n, a, e := udp.ReadFrom(b)
		if e != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(b[:n]) != nil {
			return
		}
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Truncated: true}, Questions: q.Questions}
		raw, _ := m.Pack()
		_, _ = udp.WriteTo(raw, a)
	}()
	go func() {
		conn, e := tcp.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		frame := make([]byte, 2)
		if _, e = io.ReadFull(conn, frame); e != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(frame))
		packet := make([]byte, n)
		if _, e = io.ReadFull(conn, packet); e != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(packet) != nil {
			return
		}
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}}
		raw, _ := m.Pack()
		binary.BigEndian.PutUint16(frame, uint16(len(raw)))
		_, _ = conn.Write(append(frame, raw...))
	}()
	c, _ := NewClient([]string{udp.LocalAddr().String()}, 4*time.Second)
	if len(c.Resolvers) != 1 || c.Resolvers[0] != udp.LocalAddr().String() {
		t.Fatalf("explicit fixture resolver chain changed: %v", c.Resolvers)
	}
	a, e := c.Query(context.Background(), "example.test", uint16(dnsmessage.TypeA))
	if e != nil {
		t.Fatal(e)
	}
	if len(a.Records) != 1 || a.Records[0].Value != "192.0.2.1" {
		t.Fatalf("TCP answer missing: %+v", a)
	}
}

func TestQueryRejectsTruncatedTCPResponse(t *testing.T) {
	udp, tcp := localDNSTransports(t)
	var err error
	defer udp.Close()
	defer tcp.Close()
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := udp.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil {
			return
		}
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Truncated: true}, Questions: q.Questions}
		b, _ := m.Pack()
		_, _ = udp.WriteTo(b, addr)
	}()
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var frame [2]byte
		if _, err = io.ReadFull(conn, frame[:]); err != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(frame[:])))
		if _, err = io.ReadFull(conn, query); err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(query) != nil {
			return
		}
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Truncated: true}, Questions: q.Questions}
		b, _ := m.Pack()
		binary.BigEndian.PutUint16(frame[:], uint16(len(b)))
		_, _ = conn.Write(append(frame[:], b...))
	}()
	c, err := NewClient([]string{udp.LocalAddr().String()}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Query(context.Background(), "truncated.example.test", uint16(dnsmessage.TypeA)); err == nil || !strings.Contains(err.Error(), "truncated DNS response after TCP fallback") {
		t.Fatalf("truncated TCP response accepted: %v", err)
	}
}

func TestExplicitResolverFailureNeverFallsBackOutsideFixture(t *testing.T) {
	probe, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := probe.LocalAddr().String()
	probe.Close()
	c, e := NewClient([]string{addr}, 150*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Resolvers) != 1 || c.Resolvers[0] != addr {
		t.Fatalf("explicit resolver was widened: %v", c.Resolvers)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, e = c.Query(ctx, "isolated.invalid", uint16(dnsmessage.TypeA))
	if e == nil || !strings.Contains(e.Error(), addr) {
		t.Fatalf("local resolver failure hidden by fallback: %v", e)
	}
}

func TestNewClientRejectsMissingOrInvalidResolvers(t *testing.T) {
	if _, e := NewClient(nil, time.Second); e == nil {
		t.Fatal("empty explicit resolver list accepted")
	}
	if _, e := NewClient([]string{"not-an-ip:53"}, time.Second); e == nil {
		t.Fatal("invalid resolver silently dropped")
	}
	if _, e := NewClient([]string{"[fe80::1]:53"}, time.Second); e == nil {
		t.Fatal("link-local IPv6 resolver without zone accepted")
	}
	withZone, e := NewClient([]string{"[fe80::1%12]:53"}, time.Second)
	if e != nil || withZone.Resolvers[0] != "[fe80::1%12]:53" {
		t.Fatalf("IPv6 resolver zone lost: client=%+v err=%v", withZone, e)
	}
}

func TestRateAdmissionWaitDoesNotConsumeDNSContactTimeout(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}}}}
	})
	c, err := NewClientWithRate([]string{resolver}, 500*time.Millisecond, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Query(context.Background(), "www.example.test", uint16(dnsmessage.TypeA)); err != nil {
			t.Fatalf("query %d after rate admission: %v", i+1, err)
		}
	}
}

func TestContactTimeoutSurvivesSocketCloseCancellation(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	resolver := pc.LocalAddr().String() // Local fixture intentionally receives without replying.
	c, err := NewClient([]string{resolver}, 75*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Query(context.Background(), "silent.example.test", uint16(dnsmessage.TypeA))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout cause lost when socket is closed: %v", err)
	}
}

func TestLaterResolverTimeoutIsNotHiddenByEarlierSERVFAIL(t *testing.T) {
	servfail := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RCode: dnsmessage.RCodeServerFailure}, Questions: q.Questions}
	})
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	c, err := NewClientWithRate([]string{servfail, silent.LocalAddr().String()}, 75*time.Millisecond, 10000)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Query(context.Background(), "mixed.example.test", uint16(dnsmessage.TypeA))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("later timeout hidden by previous DNS response: %v", err)
	}
}

func TestQueryPreservesMXAndSOARecordFields(t *testing.T) {
	resolver := localDNSServer(t, func(q dnsmessage.Message) dnsmessage.Message {
		owner := q.Questions[0].Name
		answer := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		switch q.Questions[0].Type {
		case dnsmessage.TypeMX:
			mx, _ := dnsmessage.NewName("Mail.Example.Test.")
			answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeMX, TTL: 60}, Body: &dnsmessage.MXResource{Pref: 10, MX: mx}}}
		case dnsmessage.TypeSOA:
			ns, _ := dnsmessage.NewName("ns.example.test.")
			mbox, _ := dnsmessage.NewName("hostmaster.example.test.")
			answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeSOA, TTL: 60}, Body: &dnsmessage.SOAResource{NS: ns, MBox: mbox, Serial: 2026101001, Refresh: 3600, Retry: 600, Expire: 604800, MinTTL: 300}}}
		case dnsmessage.TypeTXT:
			answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeTXT, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{"hello", string([]byte{'a', '"', 'b', '\\', 'c', 0, 255})}}}}
		}
		return answer
	})
	c, err := NewClient([]string{resolver}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mx, err := c.Query(context.Background(), "example.test", uint16(dnsmessage.TypeMX))
	if err != nil || len(mx.Records) != 1 || mx.Records[0].Value != "10 mail.example.test" {
		t.Fatalf("MX fields lost: %+v err=%v", mx.Records, err)
	}
	soa, err := c.Query(context.Background(), "example.test", uint16(dnsmessage.TypeSOA))
	if err != nil || len(soa.Records) != 1 || soa.Records[0].Value != "ns.example.test. hostmaster.example.test. 2026101001 3600 600 604800 300" {
		t.Fatalf("SOA fields lost: %+v err=%v", soa.Records, err)
	}
	txt, err := c.Query(context.Background(), "example.test", uint16(dnsmessage.TypeTXT))
	if err != nil || len(txt.Records) != 1 || txt.Records[0].Value != `"hello" "a\"b\\c\000\255"` {
		t.Fatalf("TXT presentation escaping lost: %+v err=%v", txt.Records, err)
	}
}

func TestConcurrentDNSContactsShareLimiterIncludingTCPFallback(t *testing.T) {
	udp, tcp := localDNSTransports(t)
	var err error
	tcpListener := tcp.(*net.TCPListener)
	_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
	_ = udp.(*net.UDPConn).SetReadDeadline(time.Now().Add(5 * time.Second))
	defer udp.Close()
	defer tcp.Close()

	var mu sync.Mutex
	contacts := make([]time.Time, 0, 4)
	recordContact := func() {
		mu.Lock()
		contacts = append(contacts, time.Now())
		mu.Unlock()
	}
	var servers sync.WaitGroup
	servers.Add(2)
	go func() {
		defer servers.Done()
		buf := make([]byte, 4096)
		for i := 0; i < 3; i++ {
			n, addr, readErr := udp.ReadFrom(buf)
			if readErr != nil {
				return
			}
			recordContact()
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				return
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
			if q.Questions[0].Name.String() == "fallback.example.test." {
				response.Header.Truncated = true
			}
			raw, packErr := response.Pack()
			if packErr != nil {
				return
			}
			if _, writeErr := udp.WriteTo(raw, addr); writeErr != nil {
				return
			}
		}
	}()
	go func() {
		defer servers.Done()
		conn, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		recordContact()
		var frame [2]byte
		if _, readErr := io.ReadFull(conn, frame[:]); readErr != nil {
			return
		}
		packet := make([]byte, int(binary.BigEndian.Uint16(frame[:])))
		if _, readErr := io.ReadFull(conn, packet); readErr != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(packet) != nil {
			return
		}
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		raw, packErr := response.Pack()
		if packErr != nil {
			return
		}
		binary.BigEndian.PutUint16(frame[:], uint16(len(raw)))
		_, _ = conn.Write(append(frame[:], raw...))
	}()

	const qps = 5.0
	c, err := NewClientWithRate([]string{udp.LocalAddr().String()}, 4*time.Second, qps)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"one.example.test", "two.example.test", "fallback.example.test"}
	var queries sync.WaitGroup
	queryErrors := make(chan error, len(names))
	for _, name := range names {
		queries.Add(1)
		go func(name string) {
			defer queries.Done()
			_, queryErr := c.Query(context.Background(), name, uint16(dnsmessage.TypeA))
			queryErrors <- queryErr
		}(name)
	}
	queries.Wait()
	close(queryErrors)
	for queryErr := range queryErrors {
		if queryErr != nil {
			t.Errorf("local DNS query failed: %v", queryErr)
		}
	}
	_ = udp.Close()
	_ = tcp.Close()
	servers.Wait()
	mu.Lock()
	got := append([]time.Time(nil), contacts...)
	mu.Unlock()
	if len(got) != 4 {
		t.Fatalf("observed %d resolver contacts, want 3 UDP plus 1 TCP: %v", len(got), got)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Before(got[j]) })
	minimum := time.Duration((1.01/qps)*float64(time.Second)) * 3 / 4
	for i := 1; i < len(got); i++ {
		if gap := got[i].Sub(got[i-1]); gap < minimum {
			t.Fatalf("shared limiter admitted resolver contacts only %s apart, minimum tolerated %s", gap, minimum)
		}
	}
}
