package blackmail

import (
	"fmt"
	"io"
	"net/mail"
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

type senderWriter struct{ w io.Writer }

func (s senderWriter) send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error {
	msg, _ := message(subject, from, rcpt, firstPart, parts...)
	fmt.Fprint(s.w, string(msg))
	return nil
}
