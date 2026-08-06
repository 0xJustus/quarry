package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

type Recorder interface {
	Start(op string, kind Kind, args string) *Span
	Record(op string, kind Kind, args, result string, err error, dur time.Duration) (Entry, error)
}

var (
	_ Recorder = (*Log)(nil)
	_ Recorder = (*scopedLog)(nil)
)

type scopedLog struct {
	parent    *Log
	principal string
	session   string
}

func (s *scopedLog) Record(op string, kind Kind, args, result string, err error, dur time.Duration) (Entry, error) {
	return s.parent.record(op, kind, args, result, err, dur, s.principal, s.session)
}

func (s *scopedLog) Start(op string, kind Kind, args string) *Span {
	return &Span{log: s.parent, op: op, kind: kind, args: args, principal: s.principal, session: s.session, start: s.parent.now()}
}

func lastEntry(path string) (*Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	var last []byte
	for sc.Scan() {
		if b := bytes.TrimSpace(sc.Bytes()); len(b) > 0 {
			last = append(last[:0], b...)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(last) == 0 {
		return nil, nil
	}
	var e Entry
	if err := json.Unmarshal(last, &e); err != nil {
		return nil, fmt.Errorf("audit: tail entry unreadable: %w", err)
	}
	return &e, nil
}

type Report struct {
	Entries uint64
	OK      bool
	Broken  uint64
	Reason  string
}

func Verify(r io.Reader) (Report, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	var (
		n        uint64
		wantSeq  uint64 = 1
		prevHash string
	)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return Report{Entries: n, Broken: wantSeq, Reason: "unparseable entry"}, nil
		}
		if e.Seq != wantSeq {
			return Report{Entries: n, Broken: e.Seq, Reason: fmt.Sprintf("seq gap: expected %d, got %d (entry deleted or reordered)", wantSeq, e.Seq)}, nil
		}
		if e.Prev != prevHash {
			return Report{Entries: n, Broken: e.Seq, Reason: "prev-hash mismatch (chain broken)"}, nil
		}
		got, err := e.computeHash()
		if err != nil {
			return Report{}, err
		}
		if got != e.Hash {
			return Report{Entries: n, Broken: e.Seq, Reason: "hash mismatch (entry edited)"}, nil
		}
		n++
		wantSeq++
		prevHash = e.Hash
	}
	if err := sc.Err(); err != nil {
		return Report{}, err
	}
	return Report{Entries: n, OK: true}, nil
}

func VerifyFile(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	return Verify(f)
}
