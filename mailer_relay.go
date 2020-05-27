package blackmail

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"sync"

	"zgo.at/blackmail/smtp"
)

// Authentication methods for MailerAuth().
const (
	AuthLogin   = "login"
	AuthPlain   = "plain"
	AuthCramMD5 = "cram-md5"
)

type senderRelay struct {
	mu *sync.Mutex

	smtp       string
	auth       string
	tls        *tls.Config
	requireTLS bool

	// Cached
	host, user, pw string
}

func (s senderRelay) send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error {
	if s.host == "" {
		srv, err := url.Parse(s.smtp)
		if err != nil {
			return err
		}
		if srv.Host == "" {
			return errors.New("blackmail.senderRelay: host empty")
		}

		s.mu.Lock()
		s.user = srv.User.Username()
		s.pw, _ = srv.User.Password()
		s.host = srv.Host // TODO: add port if not given.
		s.mu.Unlock()
	}

	msg, to, err := message(subject, from, rcpt, firstPart, parts...)
	if err != nil {
		return err
	}

	var auth smtp.Auth
	if s.user != "" {
		switch s.auth {
		case "", AuthPlain:
			auth = smtp.PlainAuth("", s.user, s.pw)
		case AuthLogin:
			auth = smtp.LoginAuth(s.user, s.pw)
		case AuthCramMD5:
			auth = smtp.CramMD5Auth(s.user, s.pw)
		default:
			return fmt.Errorf("senderRelay.send: unknown auth option: %q", s.auth)
		}
	}

	// TODO: use requireTLS
	// TODO: use tls
	err = smtp.SendMail(s.host, auth, from.Address, to, bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("senderRelay.send: %w", err)
	}
	return nil
}
