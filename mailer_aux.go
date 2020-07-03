package blackmail

import (
	"fmt"
	"io"
	"net/mail"
	"sync"
)

type (
	sender interface {
		send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error
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
