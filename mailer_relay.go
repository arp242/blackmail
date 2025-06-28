package blackmail

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"

	"zgo.at/blackmail/smtp"
)

// Authentication methods for MailerAuth().
const (
	AuthLogin   = "login"
	AuthPlain   = "plain"
	AuthCramMD5 = "cram-md5"
)

type senderRelay struct {
	host, user, pw string
	auth           string
	requireTLS     bool
	tls            *tls.Config
}

func newSenderRelay(smtp string) (senderRelay, error) {
	srv, err := url.Parse(smtp)
	if err != nil {
		return senderRelay{}, err
	}
	if srv.Host == "" {
		return senderRelay{}, errors.New("blackmail.senderRelay: host empty")
	}

	s := senderRelay{
		auth: AuthPlain,
		host: srv.Host, // TODO: add port if not given.
		user: srv.User.Username(),
	}
	s.pw, _ = srv.User.Password()
	return s, nil
}

func (s senderRelay) info() map[string]string {
	return map[string]string{
		"sender":     "senderRelay",
		"auth":       s.auth,
		"requireTLS": strconv.FormatBool(s.requireTLS),
		"host":       s.host,
		"user":       s.user,
		"pw":         s.pw,
	}
}

func (s senderRelay) send(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) error {
	msg, to, err := message(subject, from, rcpt, firstPart, parts...)
	if err != nil {
		return err
	}

	var auth smtp.Auth
	if s.user != "" {
		switch s.auth {
		case AuthPlain:
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
