package evidence

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"asmtool/internal/backends"
)

type request struct {
	path    string
	line    []byte
	barrier chan error
	close   bool
}
type eventFile struct {
	file   *os.File
	buffer *bufio.Writer
}
type Writer struct {
	q        chan request
	submitMu sync.Mutex
	errMu    sync.Mutex
	closed   bool
	fatal    error
	done     chan struct{}
	batch    int
	idle     time.Duration
}

var writerRegistry = struct {
	sync.Mutex
	writers map[*Writer]bool
}{writers: map[*Writer]bool{}}

func NewWriter(queueSize, batch int, idle time.Duration) *Writer {
	if queueSize < 1 {
		queueSize = 4096
	}
	if batch < 1 {
		batch = 128
	}
	if idle <= 0 {
		idle = 200 * time.Millisecond
	}
	w := &Writer{q: make(chan request, queueSize), done: make(chan struct{}), batch: batch, idle: idle}
	writerRegistry.Lock()
	writerRegistry.writers[w] = true
	writerRegistry.Unlock()
	go w.run()
	return w
}

func (w *Writer) enqueue(r request) error {
	w.submitMu.Lock()
	defer w.submitMu.Unlock()
	if w.closed {
		return errors.New("event writer closed")
	}
	w.errMu.Lock()
	failed := w.fatal
	w.errMu.Unlock()
	if failed != nil {
		return fmt.Errorf("event writer failed: %w", failed)
	}
	w.q <- r
	return nil
}
func (w *Writer) Append(path string, event map[string]any) error {
	if err := backends.ValidateEvent(event); err != nil {
		return err
	}
	line, err := backends.EncodeJSON(event, false, true, true)
	if err != nil {
		return err
	}
	b := make(chan error, 1)
	if err = w.enqueue(request{path: path, line: line, barrier: b}); err != nil {
		return err
	}
	return <-b
}
func (w *Writer) AppendBuffered(path string, event map[string]any) error {
	line, err := backends.EncodeJSON(event, false, true, true)
	if err != nil {
		return err
	}
	return w.enqueue(request{path: path, line: line})
}
func (w *Writer) Flush(path string) error {
	b := make(chan error, 1)
	if err := w.enqueue(request{path: path, barrier: b}); err != nil {
		return err
	}
	return <-b
}
func (w *Writer) Close() error {
	w.submitMu.Lock()
	if w.closed {
		w.submitMu.Unlock()
		<-w.done
		w.errMu.Lock()
		defer w.errMu.Unlock()
		return w.fatal
	}
	w.closed = true
	b := make(chan error, 1)
	w.q <- request{barrier: b, close: true}
	w.submitMu.Unlock()
	err := <-b
	<-w.done
	writerRegistry.Lock()
	delete(writerRegistry.writers, w)
	writerRegistry.Unlock()
	return err
}

func (w *Writer) run() {
	defer close(w.done)
	handles := map[string]*eventFile{}
	dirty := map[string]int{}
	var first error
	timer := time.NewTicker(w.idle)
	defer timer.Stop()
	flush := func(path string) error {
		for p, f := range handles {
			if path != "" && p != path {
				continue
			}
			if path == "" && dirty[p] == 0 {
				continue
			}
			if e := f.buffer.Flush(); e != nil {
				return e
			}
			dirty[p] = 0
		}
		return nil
	}
	closeFiles := func() error {
		var errs []error
		for p, f := range handles {
			if dirty[p] > 0 {
				if x := f.buffer.Flush(); x != nil {
					errs = append(errs, fmt.Errorf("flush %s: %w", p, x))
				}
			}
			if x := f.file.Close(); x != nil {
				errs = append(errs, fmt.Errorf("close %s: %w", p, x))
			}
			delete(handles, p)
		}
		return errors.Join(errs...)
	}
	for {
		select {
		case <-timer.C:
			if first == nil {
				if e := flush(""); e != nil {
					first = e
					w.errMu.Lock()
					w.fatal = e
					w.errMu.Unlock()
					if closeErr := closeFiles(); closeErr != nil {
						first = errors.Join(first, closeErr)
						w.errMu.Lock()
						w.fatal = first
						w.errMu.Unlock()
					}
				}
			}
		case r := <-w.q:
			var err error
			if first != nil {
				err = first
			}
			if r.close {
				if e := closeFiles(); err == nil {
					err = e
				}
			} else if err == nil && r.barrier != nil && len(r.line) == 0 {
				err = flush(r.path)
			} else if err == nil {
				f := handles[r.path]
				if f == nil {
					if e := os.MkdirAll(filepath.Dir(r.path), 0755); e != nil {
						err = e
					} else if file, openErr := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); openErr != nil {
						err = openErr
					} else {
						f = &eventFile{file: file, buffer: bufio.NewWriterSize(file, 256*1024)}
						handles[r.path] = f
					}
				}
				if err == nil {
					v, x := backends.DecodeJSON(bytes.TrimSpace(r.line))
					if x != nil {
						err = x
					} else if ev, ok := v.(map[string]any); !ok {
						err = errors.New("event JSON must be an object")
					} else if x = backends.ValidateEvent(ev); x != nil {
						err = x
					}
				}
				if err == nil {
					_, err = f.buffer.Write(r.line)
					dirty[r.path]++
					if err == nil && (r.barrier != nil || dirty[r.path] >= w.batch) {
						err = f.buffer.Flush()
						if err == nil {
							dirty[r.path] = 0
						}
					}
				}
			}
			if err != nil && first == nil {
				first = err
				if closeErr := closeFiles(); closeErr != nil {
					first = errors.Join(first, closeErr)
				}
				w.errMu.Lock()
				w.fatal = first
				w.errMu.Unlock()
			}
			if r.barrier != nil {
				r.barrier <- err
			}
			if r.close {
				return
			}
		}
	}
}

type JSONLRecord struct {
	Path  string
	Line  int
	Event map[string]any
	Err   error
}

// IterJSONL reports each rejected input with its path and line while continuing.
func IterJSONL(path string, visit func(JSONLRecord) error) error {
	if e := flushWritersFor(path); e != nil {
		return e
	}
	f, e := os.Open(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 64*1024*1024)
	line := 0
	for s.Scan() {
		line++
		raw := bytes.TrimSpace(s.Bytes())
		if len(raw) == 0 {
			continue
		}
		v, e := backends.DecodeJSON(raw)
		if e == nil {
			m, ok := v.(map[string]any)
			if !ok {
				e = errors.New("JSONL value must be object")
			} else if e = backends.ValidateEvent(m); e == nil {
				if x := visit(JSONLRecord{Path: path, Line: line, Event: m}); x != nil {
					return x
				}
				continue
			}
		}
		if x := visit(JSONLRecord{Path: path, Line: line, Err: e}); x != nil {
			return x
		}
	}
	return s.Err()
}

func flushWritersFor(_ string) error {
	writerRegistry.Lock()
	var writers []*Writer
	for w := range writerRegistry.writers {
		writers = append(writers, w)
	}
	writerRegistry.Unlock()
	for _, w := range writers {
		if err := w.Flush(""); err != nil {
			w.submitMu.Lock()
			closed := w.closed
			w.submitMu.Unlock()
			if !closed {
				return err
			}
			<-w.done
			w.errMu.Lock()
			fatal := w.fatal
			w.errMu.Unlock()
			if fatal != nil {
				return fatal
			}
		}
	}
	return nil
}

var defaultOnce sync.Once
var defaultWriterMu sync.Mutex
var defaultEventsWriter *Writer

func defaultWriter() *Writer {
	defaultWriterMu.Lock()
	defaultOnce.Do(func() { defaultEventsWriter = NewWriter(4096, 128, 200*time.Millisecond) })
	defaultWriterMu.Unlock()
	return defaultEventsWriter
}
func AppendEvent(path string, event map[string]any) error { return defaultWriter().Append(path, event) }
func AppendEventBuffered(path string, event map[string]any) error {
	return defaultWriter().AppendBuffered(path, event)
}
func FlushEventWriters(path string) error { return defaultWriter().Flush(path) }
func CloseEventWriters() error {
	return defaultWriter().Close()
}
