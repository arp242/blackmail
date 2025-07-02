package blackmail

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"strings"

	"zgo.at/blackmail/smtp"
)

type mailerRelay struct {
	url, addr, user, pw string
	opts                RelayOptions
	smtps               bool
	tls                 *tls.Config
}

type RelayOptions struct {
	// Auth sets the AUTH method; currently LOGIN, PLAIN, and CRAM-MD5 are
	// supported.
	//
	// In general, PLAIN is preferred and is the default. Note that CRAM-MD5
	// only provides weak security over untrusted connections.
	Auth smtp.AuthMethod

	// TLS configuration for smtps and STARTTLS.
	TLS *tls.Config

	Debug io.Writer
}

func (o RelayOptions) String() string {
	return fmt.Sprintf("auth=%q; debug=%v; tls=%v", o.Auth, o.Debug, o.TLS)
}

// NewRelay returns a new relay mailer.
//
// Any URL will be used as a SMTP relay; "smtp://" for unencrypted or STARTTLS
// connections, and "smtps://" for TLS connections.
//
// For example:
//
//	"smtp://user:pass@mail.example.com:587"
//	"smtps://user:pass@mail.example.com"
func NewRelay(smtpURL string, opts *RelayOptions) (Mailer, error) {
	if opts == nil {
		opts = &RelayOptions{}
	}

	srv, err := url.Parse(smtpURL)
	if err != nil {
		return nil, err
	}
	if srv.Host == "" {
		return nil, errors.New("blackmail.NewRelay: host empty")
	}

	s := mailerRelay{
		url:  smtpURL,
		opts: *opts, //smtp.AuthPlain,
		addr: srv.Host,
		user: srv.User.Username(),
	}
	switch srv.Scheme {
	case "smtp":
	case "smtps":
		s.smtps, s.tls = true, opts.TLS
		if s.tls == nil {
			s.tls = &tls.Config{}
		}
	default:
		return nil, errors.New("blackmail.NewRelay: scheme empty")
	}

	s.pw, _ = srv.User.Password()
	if !strings.Contains(s.addr, ":") {
		if srv.Scheme == "smtps" {
			s.addr += ":587"
		} else {
			s.addr += ":25"
		}
	}
	return &s, nil
}

func (s mailerRelay) Info() map[string]any {
	return map[string]any{
		"sender": "mailerRelay",
		"url":    s.url,
		"smtps":  s.smtps,
		"opts":   s.opts,
		"addr":   s.addr,
		"user":   s.user,
		"pw":     s.pw,
	}
}

func (s mailerRelay) Send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error {
	msg, to, err := message(subject, from, rcpt, firstPart, parts...)
	if err != nil {
		return err
	}

	var c *smtp.Client
	if s.smtps {
		c, err = smtp.DialTLS(s.addr, s.tls)
	} else {
		c, err = smtp.Dial(s.addr)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	c.DebugWriter = s.opts.Debug

	if ok, _ := c.Extension("STARTTLS"); ok {
		err := c.StartTLS(nil)
		if err != nil {
			return err
		}
	}

	if s.user != "" {
		ok, a := c.Extension("AUTH")
		if !ok {
			return errors.New("mailerRelay.send: server doesn't support AUTH")
		}
		if s.opts.Auth == "" {
			for _, aa := range strings.Split(strings.ToLower(a), " ") {
				switch aa {
				case "plain":
					s.opts.Auth = smtp.AuthPlain
				case "login":
					s.opts.Auth = smtp.AuthLogin
				case "cram-md5":
					s.opts.Auth = smtp.AuthCramMD5
				}
				if s.opts.Auth != "" {
					break
				}
			}
		}
		var err error
		switch s.opts.Auth {
		case smtp.AuthPlain:
			err = c.Auth(smtp.PlainAuth("", s.user, s.pw))
		case smtp.AuthLogin:
			err = c.Auth(smtp.LoginAuth(s.user, s.pw))
		case smtp.AuthCramMD5:
			err = c.Auth(smtp.CramMD5Auth(s.user, s.pw))
		default:
			err = fmt.Errorf("mailerRelay.send: unknown auth option: %q", s.opts.Auth)
		}
		if err != nil {
			return err
		}
	}

	err = c.SendMail(from.Address, to, bytes.NewReader(msg))
	if err != nil {
		return err
	}
	return c.Close()
}
