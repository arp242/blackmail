package blackmail

// This file contains the public API to send messages.

import (
	"crypto/tls"
	"io"
	"net/mail"
	"sync"
)

// Mailer to send messages; use NewMailer() to construct a new instance.
type Mailer struct{ sender sender }

const (
	ConnectWriter = "writer" // Write to an io.Writer.
	ConnectDirect = "direct" // Connect directly to MX records.
)

// DefaultMailer is used with blackmail.Send().
var DefaultMailer = NewMailer(ConnectDirect)

// MailerOut sets the output for the writer mailer.
func MailerOut(v io.Writer) senderOpt {
	return func(s sender) {
		sw, ok := s.(*senderWriter)
		if ok {
			sw.w = v
			return
		}
		warn("MailerOut", s)
	}
}

// MailerAuth sets the AUTH method for the relay mailer. Currently LOGIN, PLAIN,
// and CRAM-MD5 are supported.
//
// In general, PLAIN is preferred and it's the default. Note that CRAM-MD5 only
// provides weak security over untrusted connections.
func MailerAuth(v string) senderOpt {
	return func(s sender) {
		sr, ok := s.(*senderRelay)
		if ok {
			sr.auth = v
			return
		}
		warn("MailerAuth", s)
	}
}

// MailerTLS sets the tls config for the relay and direct mailer.
func MailerTLS(v *tls.Config) senderOpt {
	return func(s sender) {
		sr, ok := s.(*senderRelay)
		if ok {
			sr.tls = v
			return
		}
		sd, ok := s.(*senderDirect)
		if ok {
			sd.tls = v
			return
		}
		warn("MailerTLS", s)
	}
}

// MailerRequireTLS sets whether TLS is required.
func MailerRequireTLS(v bool) senderOpt {
	return func(s sender) {
		sr, ok := s.(*senderRelay)
		if ok {
			sr.requireTLS = v
			return
		}
		sd, ok := s.(*senderDirect)
		if ok {
			sd.requireTLS = v
			return
		}
		warn("MailerRequireSTARTTLS", s)
	}
}

// NewMailer returns a new re-usable mailer.
//
// Setting the connection string to blackmail.Writer will print all messages to
// stdout without sending them:
//
//   NewMailer(blackmail.Writer)
//
// You can pass Mailer.Writer() as an option to send them somewhere else:
//
//   NewMailer(blackmail.Writer, blackmail.MailerOut(os.Stderr))
//
//   buf := new(bytes.Buffer)
//   NewMailer(blackmail.Writer, blackmail.MailerOut(buf))
//
// If the connection string is set to blackmail.Direct, blackmail will look up
// the MX records and attempt to deliver to them.
//
//   NewMailer(blackmail.Direct)
//
// Any URL will be used as a SMTP relay:
//
//   NewMailer("smtps://foo:foo@mail.foo.com")
//
// The default authentication is PLAIN; add MailerAuth() to set something
// different.
func NewMailer(smtp string, opts ...senderOpt) Mailer {
	var m Mailer
	switch smtp {
	case ConnectWriter:
		s := senderWriter{w: stdout}
		for _, o := range opts {
			o(&s)
		}
		m = Mailer{sender: s}

	case ConnectDirect:
		m = Mailer{sender: senderDirect{}}
	default:
		m = Mailer{sender: senderRelay{
			smtp: smtp,
			mu:   new(sync.Mutex),
		}}
	}

	return m
}

// Send an email.
//
// The arguments are identical to Message().
func (m Mailer) Send(subject string, from mail.Address, rcpt []recipient, parts ...bodyPart) error {
	return m.sender.send(subject, from, rcpt, parts...)
}

// Send an email using the DefaultMailer.
//
// The arguments are identical to Message().
func Send(subject string, from mail.Address, rcpt []recipient, parts ...bodyPart) error {
	return DefaultMailer.Send(subject, from, rcpt, parts...)
}
