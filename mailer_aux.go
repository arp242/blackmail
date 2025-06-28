package blackmail

import (
	"fmt"
	"io"
	"net/mail"
	"os"
	"strconv"
	"sync"
)

type (
	sender interface {
		send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error
		info() map[string]string
	}
	senderOpt func(sender)
)

func warn(opt string, s sender) {
	fmt.Fprintf(stderr, "blackmail.NewMailer: %s is not valid for %T; option ignored\n", opt, s)
}

type senderWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func newSenderWriter(opts []senderOpt) (senderWriter, error) {
	s := senderWriter{w: stdout, mu: new(sync.Mutex)}
	for _, o := range opts {
		o(&s)
	}
	return s, nil
}

func (s senderWriter) info() map[string]string {
	if fp, ok := s.w.(*os.File); ok {
		return map[string]string{
			"sender": "senderDirect",
			"fd":     strconv.FormatUint(uint64(fp.Fd()), 10),
			"name":   fp.Name(),
		}
	}
	return map[string]string{
		"sender": "senderDirect",
		"w":      fmt.Sprintf("%T", s.w),
	}
}

func (s senderWriter) send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error {
	msg, _, err := message(subject, from, rcpt, firstPart, parts...)
	if err != nil {
		return err
	}

	s.mu.Lock()
	fmt.Fprint(s.w, string(msg))
	s.mu.Unlock()
	return nil
}
