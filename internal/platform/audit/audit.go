package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Kind string

const (
	KindCall       Kind = "call"
	KindSideEffect Kind = "sideeffect"
	KindAccess     Kind = "access"
)

type Entry struct {
	Seq       uint64 `json:"seq"`
	Prev      string `json:"prev"`
	TS        string `json:"ts"`
	Principal string `json:"principal"`
	Session   string `json:"session,omitempty"`
	Op        string `json:"op"`
	Kind      Kind   `json:"kind"`
	Args      string `json:"args,omitempty"`
	Result    string `json:"result,omitempty"`
	Err       string `json:"err,omitempty"`
	DurMS     int64  `json:"dur_ms,omitempty"`
	Hash      string `json:"hash"`
}

// Entry fields hash in declaration order; reordering them changes every Hash and breaks the chain.
func (e Entry) preimage() ([]byte, error) {
	e.Hash = ""
	return json.Marshal(e)
}

func (e Entry) computeHash() (string, error) {
	b, err := e.preimage()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type Sink interface {
	Emit(Entry) error
}

type WriterSink struct{ W io.Writer }

func (s WriterSink) Emit(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.W.Write(append(b, '\n'))
	return err
}

type Log struct {
	mu        sync.Mutex
	w         io.Writer
	closer    io.Closer
	seq       uint64
	prev      string
	sinks     []Sink
	principal string
	session   string
	now       func() time.Time
	subs      []chan Entry
	sinkErr   error
}

type Option func(*Log)

func WithPrincipal(p string) Option { return func(l *Log) { l.principal = p } }
func WithSession(s string) Option   { return func(l *Log) { l.session = s } }

func WithSink(s Sink) Option { return func(l *Log) { l.sinks = append(l.sinks, s) } }

func WithClock(now func() time.Time) Option { return func(l *Log) { l.now = now } }

func Open(path string, opts ...Option) (*Log, error) {
	last, err := lastEntry(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{w: f, closer: f, now: time.Now}
	if last != nil {
		want, err := last.computeHash()
		if err != nil {
			f.Close()
			return nil, err
		}
		if want != last.Hash {
			f.Close()
			return nil, fmt.Errorf("audit: refusing to extend a tampered log %q: tail seq %d hash mismatch", path, last.Seq)
		}
		l.seq = last.Seq
		l.prev = last.Hash
	}
	for _, o := range opts {
		o(l)
	}
	return l, nil
}

func NewWriter(w io.Writer, opts ...Option) *Log {
	l := &Log{w: w, now: time.Now}
	for _, o := range opts {
		o(l)
	}
	return l
}

func (l *Log) Sub(principal, session string) *scopedLog {
	return &scopedLog{parent: l, principal: principal, session: session}
}

func (l *Log) Record(op string, kind Kind, args, result string, callErr error, dur time.Duration) (Entry, error) {
	return l.record(op, kind, args, result, callErr, dur, l.principal, l.session)
}

func (l *Log) record(op string, kind Kind, args, result string, callErr error, dur time.Duration, principal, session string) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := Entry{
		Seq:       l.seq,
		Prev:      l.prev,
		TS:        l.now().UTC().Format(time.RFC3339Nano),
		Principal: principal,
		Session:   session,
		Op:        op,
		Kind:      kind,
		Args:      args,
		Result:    result,
	}
	if callErr != nil {
		e.Err = callErr.Error()
	}
	if dur > 0 {
		e.DurMS = dur.Milliseconds()
	}
	h, err := e.computeHash()
	if err != nil {
		l.seq--
		return Entry{}, err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		l.seq--
		return Entry{}, err
	}
	if _, err := l.w.Write(append(line, '\n')); err != nil {
		l.seq--
		return Entry{}, fmt.Errorf("audit: append: %w", err)
	}
	l.prev = e.Hash
	for _, s := range l.sinks {
		if err := s.Emit(e); err != nil && l.sinkErr == nil {
			l.sinkErr = err
		}
	}
	for _, ch := range l.subs {
		select {
		case ch <- e:
		default:
		}
	}
	return e, nil
}

func (l *Log) Subscribe(buffer int) (<-chan Entry, func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ch := make(chan Entry, buffer)
	l.subs = append(l.subs, ch)
	cancel := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		for i, c := range l.subs {
			if c == ch {
				l.subs = append(l.subs[:i], l.subs[i+1:]...)
				close(ch)
				break
			}
		}
	}
	return ch, cancel
}

func (l *Log) SinkErr() error { l.mu.Lock(); defer l.mu.Unlock(); return l.sinkErr }

func (l *Log) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

type Span struct {
	log       *Log
	op        string
	kind      Kind
	args      string
	principal string
	session   string
	start     time.Time
}

func (l *Log) Start(op string, kind Kind, args string) *Span {
	return &Span{log: l, op: op, kind: kind, args: args, principal: l.principal, session: l.session, start: l.now()}
}

func (s *Span) End(result string, err error) (Entry, error) {
	return s.log.record(s.op, s.kind, s.args, result, err, s.log.now().Sub(s.start), s.principal, s.session)
}
