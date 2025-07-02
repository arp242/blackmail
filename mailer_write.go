package blackmail

import (
	"fmt"
	"io"
	"net/mail"
	"os"
	"strconv"
	"sync"
)

type mailerWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter creates a writer mailer, which writes to w. Mainly for test and dev
// setups.
func NewWriter(w io.Writer) Mailer {
	return &mailerWriter{w: w}
}

func (s *mailerWriter) Info() map[string]any {
	if fp, ok := s.w.(*os.File); ok {
		return map[string]any{
			"sender": "mailerWriter",
			"fd":     strconv.FormatUint(uint64(fp.Fd()), 10),
			"name":   fp.Name(),
		}
	}
	return map[string]any{
		"sender": "mailerWriter",
		"w":      fmt.Sprintf("%T", s.w),
	}
}

func (s *mailerWriter) Send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error {
	msg, _, err := message(subject, from, rcpt, firstPart, parts...)
	if err != nil {
		return err
	}

	s.mu.Lock()
	fmt.Fprint(s.w, string(msg))
	fmt.Fprintln(s.w)
	s.mu.Unlock()
	return nil
}
