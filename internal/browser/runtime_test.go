package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"asmtool/internal/execution"
	"asmtool/internal/platform"
)

func TestValidateControlURLRequiresSelectedBrowserEndpoint(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		want bool
	}{
		{name: "valid", url: "ws://127.0.0.1:9222/devtools/browser/abc", want: true},
		{name: "wrong host", url: "ws://localhost:9222/devtools/browser/abc"},
		{name: "wrong port", url: "ws://127.0.0.1:9223/devtools/browser/abc"},
		{name: "target websocket", url: "ws://127.0.0.1:9222/devtools/page/abc"},
		{name: "userinfo", url: "ws://user@127.0.0.1:9222/devtools/browser/abc"},
		{name: "query", url: "ws://127.0.0.1:9222/devtools/browser/abc?redirect=1"},
		{name: "secure scheme", url: "wss://127.0.0.1:9222/devtools/browser/abc"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateControlURL(test.url, 9222)
			if (err == nil) != test.want {
				t.Fatalf("validateControlURL(%q) error=%v", test.url, err)
			}
		})
	}
}

func TestWaitForControlEndpointUsesBoundedLoopbackAndRejectsRedirects(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request, int)
		wantErr bool
	}{
		{
			name: "valid endpoint",
			handler: func(w http.ResponseWriter, _ *http.Request, port int) {
				_, _ = fmt.Fprintf(w, `{"webSocketDebuggerUrl":"ws://127.0.0.1:%d/devtools/browser/id"}`, port)
			},
		},
		{
			name: "redirect",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.Header().Set("Location", "http://192.0.2.1/")
				w.WriteHeader(http.StatusFound)
			},
			wantErr: true,
		},
		{
			name: "external websocket endpoint",
			handler: func(w http.ResponseWriter, _ *http.Request, port int) {
				_, _ = fmt.Fprintf(w, `{"webSocketDebuggerUrl":"ws://192.0.2.1:%d/devtools/browser/id"}`, port)
			},
			wantErr: true,
		},
		{
			name: "oversized response",
			handler: func(w http.ResponseWriter, _ *http.Request, port int) {
				_, _ = fmt.Fprintf(w, `{"webSocketDebuggerUrl":"ws://127.0.0.1:%d/devtools/browser/%s"}`, port, strings.Repeat("x", readinessBodyMax))
			},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			mux := http.NewServeMux()
			mux.HandleFunc("/json/version", func(w http.ResponseWriter, r *http.Request) {
				test.handler(w, r, port)
			})
			server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(listener) }()
			t.Cleanup(func() {
				_ = server.Close()
				<-serveDone
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			endpoint, err := waitForControlEndpoint(ctx, port, make(chan struct{}))
			if test.wantErr {
				if err == nil {
					t.Fatalf("accepted endpoint %q", endpoint)
				}
				return
			}
			want := "ws://127.0.0.1:" + strconv.Itoa(port) + "/devtools/browser/id"
			if err != nil || endpoint != want {
				t.Fatalf("endpoint=%q err=%v want %q", endpoint, err, want)
			}
		})
	}
}

func TestOwnedProcessCancellationJoinsRunner(t *testing.T) {
	started := make(chan struct{})
	plan := LaunchPlan{run: func(ctx context.Context, _ platform.Tool, _ []string, _ execution.Options) (execution.Result, error) {
		close(started)
		<-ctx.Done()
		return execution.Result{}, ctx.Err()
	}}
	process := startOwnedProcess(context.Background(), plan)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := process.Close(ctx); err != nil {
		t.Fatalf("close canceled process: %v", err)
	}
	select {
	case <-process.done:
	case <-time.After(time.Second):
		t.Fatal("runner did not join")
	}
	if out := process.outcome(); !errors.Is(out.err, context.Canceled) {
		t.Fatalf("runner outcome error = %v", out.err)
	}
}

func TestReadinessRejectsAlreadyExitedProcess(t *testing.T) {
	portListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	if err := portListener.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := waitForControlEndpoint(ctx, port, done); err == nil {
		t.Fatal("accepted already exited process")
	}
}

func TestOwnedProcessCloseRetainsCleanupErrorJoinedWithCancellation(t *testing.T) {
	cleanupErr := errors.New("simulated cleanup failure")
	process := &ownedProcess{cancel: func() {}, done: make(chan struct{}), out: processOutcome{err: errors.Join(context.Canceled, cleanupErr)}}
	close(process.done)
	if err := process.Close(context.Background()); !errors.Is(err, cleanupErr) {
		t.Fatalf("cleanup error was lost: %v", err)
	}
}
