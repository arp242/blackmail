package blackmail

// This file contains the public API to send messages.

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/mail"
	"os"
	"sync"
	"time"

	"zgo.at/blackmail/sg"
)

// Mailer to send messages; use NewMailer() to construct a new instance.
type Mailer interface {
	Send(subject string, from mail.Address, parts ...Part) error
}

// DefaultMailer is used with blackmail.Send().
var DefaultMailer = NewMailerWriter(os.Stderr)

// Send an email using the DefaultMailer.
//
// The arguments are identical to Message().
func Send(subject string, from mail.Address, parts ...Part) error {
	return DefaultMailer.Send(subject, from, parts...)
}

// NewMailerWriter returns a mailer which merely writes the message to an
// io.Writer.
func NewMailerWriter(w io.Writer) Mailer {
	return mailerWriter{w: w, mu: new(sync.Mutex)}
}

// NewMailerSMTP returns a mailer which uses SMTP to send messages.
//
// By default blackmail will look up the MX records and attempt to deliver to
// them.
//
// In many cases you want to use a SMTP relay;
//
//   NewMailerSMTP(MailerRelay("smtps://foo:foo@mail.foo.com"))
//
// Other options:
//
//   NewMailerSMTP(
//		MailerRelay("smtps://foo:foo@mail.foo.com"),
//		MailerAuth(),
//		MailerTLS(),
//		MailerRequireTLS(true))
func NewMailerSMTP(opts ...smtpOpt) Mailer {
	m := mailerSMTP{mu: new(sync.Mutex)}
	for _, o := range opts {
		o(&m)
	}
	return m
}

type smtpOpt func(m *mailerSMTP)

// Authentication methods for MailerAuth().
const (
	AuthLogin   = "login"
	AuthPlain   = "plain"
	AuthCramMD5 = "cram-md5"
)

// MailerRelay sets an SMTP to use as a relay.
func MailerRelay(url string) smtpOpt { return func(m *mailerSMTP) { m.relay = url } }

// MailerAuth sets the AUTH method for the relay mailer. Currently LOGIN, PLAIN,
// and CRAM-MD5 are supported.
//
// In general, PLAIN is preferred and it's the default. Note that CRAM-MD5 only
// provides weak security over untrusted connections.
func MailerAuth(v string) smtpOpt { return func(m *mailerSMTP) { m.auth = v } }

// MailerTLS sets the tls config for the relay and direct mailer.
func MailerTLS(v *tls.Config) smtpOpt { return func(m *mailerSMTP) { m.tls = v } }

// MailerRequireTLS sets whether TLS is required.
func MailerRequireTLS(v bool) smtpOpt { return func(m *mailerSMTP) { m.requireTLS = v } }

// NewMailerSendGrid creates a new SendGrid mailer.
//
// A http.Client with a timeout of 10 seconds will be used if no http.Client is
// given.
func NewMailerSendGrid(apiKey string, opts ...sgOpt) Mailer {
	m := mailerSendGrid{apiKey: apiKey}
	for _, o := range opts {
		o(&m)
	}
	if m.httpC == nil {
		m.httpC = &http.Client{Timeout: 10 * time.Second}
	}
	return m
}

type sgOpt func(m *mailerSendGrid)

func MailerHTTPClient(client *http.Client) sgOpt { return func(m *mailerSendGrid) { m.httpC = client } }
func MailerModify(mod func(*sg.Message)) sgOpt   { return func(m *mailerSendGrid) { m.mod = mod } }
func MailerSandbox(enable bool) sgOpt            { return func(m *mailerSendGrid) { m.sandbox = enable } }
