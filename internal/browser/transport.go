package browser

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-rod/rod/lib/cdp"
	"golang.org/x/net/websocket"
)

// Only the local CDP control transport. No HTTP target transport, broker,
// resolver fallback, launcher, browser download or Rod helper runtime is used.
type rodTransport struct {
	client    *cdp.Client
	socket    io.Closer
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	once      sync.Once
	closeErr  error
	timeout   time.Duration
	eventMu   sync.Mutex
	documents map[string]*documentResponseCollector
}

type checkedSocket struct {
	cdp.WebSocketable
	max int
}

func (s checkedSocket) Send(data []byte) error {
	if len(data) > s.max {
		return errors.New("CDP command exceeds byte limit")
	}
	return s.WebSocketable.Send(data)
}

func (s checkedSocket) Read() ([]byte, error) {
	data, err := s.WebSocketable.Read()
	if err != nil {
		return nil, err
	}
	// Validate the exact Rod decoding shapes before they reach its panic-on-error
	// parser. Native responses/events are untrusted, even on a loopback socket.
	if len(data) > s.max || !utf8.Valid(data) || !json.Valid(data) {
		return nil, errors.New("malformed or oversized CDP packet")
	}
	var identity struct {
		ID int `json:"id"`
	}
	if err = json.Unmarshal(data, &identity); err != nil || identity.ID < 0 {
		return nil, errors.New("invalid CDP packet identity")
	}
	if identity.ID == 0 {
		var event cdp.Event
		if err = json.Unmarshal(data, &event); err != nil || event.Method == "" || (len(event.Params) > 0 && event.Params[0] != '{') {
			return nil, errors.New("invalid CDP event")
		}
	} else {
		var response cdp.Response
		if err = json.Unmarshal(data, &response); err != nil || (response.Error == nil && (len(response.Result) == 0 || response.Result[0] != '{')) {
			return nil, errors.New("invalid CDP response")
		}
	}
	return data, nil
}

// newRodTransport is private; controller tests use a memory socket.
func newRodTransport(parent context.Context, socket interface {
	cdp.WebSocketable
	io.Closer
}, max int, timeout time.Duration) (*rodTransport, error) {
	if parent == nil || socket == nil || max <= 0 || max > 32<<20 || timeout <= 0 || timeout > 20*time.Second {
		return nil, errors.New("invalid CDP transport bounds")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	r := &rodTransport{socket: socket, ctx: ctx, cancel: cancel, done: make(chan struct{}), timeout: timeout, documents: make(map[string]*documentResponseCollector)}
	r.client = cdp.New().Logger(log.New(io.Discard, "", 0)).Start(checkedSocket{socket, max})
	go func() {
		defer close(r.done)
		for event := range r.client.Event() {
			r.eventMu.Lock()
			if collector := r.documents[event.SessionID]; collector != nil {
				_ = collector.Ingest(event.SessionID, event.Method, event.Params)
			}
			r.eventMu.Unlock()
		}
	}()
	context.AfterFunc(ctx, r.closeSocket)
	return r, nil
}

// Subscription precedes Page.navigate. Events describe observations only;
// neither this collector nor CDP Fetch authorizes network connections.
func (r *rodTransport) observeDocument(session string) (*documentResponseCollector, func(), error) {
	c, err := newDocumentResponseCollector(EventLimits{512, 64 << 10, 2 << 20, 32 << 10})
	if err != nil {
		return nil, nil, err
	}
	if err := c.SetSession(session); err != nil {
		return nil, nil, err
	}
	r.eventMu.Lock()
	defer r.eventMu.Unlock()
	if session == "" || r.documents[session] != nil {
		return nil, nil, errors.New("invalid or concurrent document subscription")
	}
	r.documents[session] = c
	return c, func() { r.eventMu.Lock(); delete(r.documents, session); r.eventMu.Unlock() }, nil
}

func (r *rodTransport) Call(parent context.Context, sessionID, method string, params any) ([]byte, error) {
	if parent == nil {
		return nil, errors.New("nil CDP command context")
	}
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Rod marshals with panic-on-error; reject invalid parameter values first.
	if _, err := json.Marshal(params); err != nil {
		return nil, err
	}
	// Rod Send is synchronous. Cancelling any command tears down the owned
	// connection, unblocking a write as well as a pending reply.
	stopCommand := context.AfterFunc(ctx, func() { r.cancel(); r.closeSocket() })
	defer stopCommand()
	return r.client.Call(ctx, sessionID, method, params)
}

func (r *rodTransport) Close() error {
	r.cancel()
	r.closeSocket()
	timer := time.NewTimer(r.timeout)
	defer timer.Stop()
	select {
	case <-r.done:
		return r.closeErr
	case <-timer.C:
		return errors.Join(r.closeErr, errors.New("CDP event reader cleanup timed out"))
	}
}

func (r *rodTransport) closeSocket() { r.once.Do(func() { r.closeErr = r.socket.Close() }) }

type nativeControlSocket struct {
	*websocket.Conn
	timeout time.Duration
}

func (s nativeControlSocket) Send(data []byte) error {
	if err := s.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	return websocket.Message.Send(s.Conn, string(data))
}
func (s nativeControlSocket) Read() ([]byte, error) {
	var data []byte
	err := websocket.Message.Receive(s.Conn, &data)
	return data, err
}

// Direct CDP connection to the selected literal loopback endpoint validated
// during readiness. No environment proxy or URL lookup is used.
func connectControl(ctx context.Context, raw string, port int, opts Options) (*rodTransport, error) {
	if ctx == nil {
		return nil, errors.New("nil CDP connection context")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	u, err := validateControlURL(raw, port)
	if err != nil {
		return nil, err
	}
	conf, err := websocket.NewConfig(u.String(), "http://127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	conf.Dialer = &net.Dialer{Timeout: opts.CommandTimeout}
	connCtx, cancel := context.WithTimeout(ctx, opts.CommandTimeout)
	defer cancel()
	conn, err := conf.DialContext(connCtx)
	if err != nil {
		return nil, err
	}
	conn.MaxPayloadBytes = opts.MaxResultBytes
	r, err := newRodTransport(ctx, nativeControlSocket{conn, opts.CommandTimeout}, opts.MaxResultBytes, opts.CommandTimeout)
	if err != nil {
		_ = conn.Close()
	}
	return r, err
}
