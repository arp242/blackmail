package blackmail

import (
	"fmt"
	"io"
	"net/mail"
	"sync"
)

type mailerWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (m mailerWriter) Send(subject string, from mail.Address, parts ...Part) error {
	msg, _, err := message(subject, from, parts...)
	if err != nil {
		return err
	}

	m.mu.Lock()
	fmt.Fprint(m.w, string(msg))
	m.mu.Unlock()
	return nil
}
