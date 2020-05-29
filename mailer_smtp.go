package blackmail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"sync"

	"zgo.at/blackmail/smtp"
)

type mailerSMTP struct {
	mu *sync.Mutex

	relay      string
	auth       string
	tls        *tls.Config
	requireTLS bool

	// Cached
	host, user, pw string
}

func (m mailerSMTP) Send(subject string, from mail.Address, parts ...Part) error {
	if m.relay != "" {
		err := m.sendRelay(subject, from, parts...)
		if err != nil {
			return fmt.Errorf("blackmail.mailerSMTP: %w", err)
		}
		return nil
	}
	err := m.sendDirect(subject, from, parts...)
	if err != nil {
		return fmt.Errorf("blackmail.mailerSMTP: %w", err)
	}
	return nil
}

func (m mailerSMTP) sendRelay(subject string, from mail.Address, parts ...Part) error {
	if m.host == "" {
		srv, err := url.Parse(m.relay)
		if err != nil {
			return err
		}
		if srv.Host == "" {
			return errors.New("sendRelay: relay host empty")
		}

		m.mu.Lock()
		m.user = srv.User.Username()
		m.pw, _ = srv.User.Password()
		m.host = srv.Host // TODO: add port if not given.
		m.mu.Unlock()
	}

	msg, to, err := message(subject, from, parts...)
	if err != nil {
		return err
	}

	var auth smtp.Auth
	if m.user != "" {
		switch m.auth {
		case "":
		case AuthPlain:
			auth = smtp.PlainAuth("", m.user, m.pw)
		case AuthLogin:
			auth = smtp.LoginAuth(m.user, m.pw)
		case AuthCramMD5:
			auth = smtp.CramMD5Auth(m.user, m.pw)
		default:
			return fmt.Errorf("sendRelay: unknown auth option: %q", m.auth)
		}
	}

	err = smtp.Send(m.host, from.Address, to, msg,
		smtp.SendAuth(auth), smtp.SendTLS(m.tls), smtp.SendRequireTLS(m.requireTLS))
	if err != nil {
		return fmt.Errorf("senderRelay: send: %w", err)
	}
	return nil
}

var hostname sync.Once

// TODO: use requireStartTLS
// TODO: use tls
func (s mailerSMTP) sendDirect(subject string, from mail.Address, parts ...Part) error {
	panic("WIP")

	msg, to, err := message(subject, from, parts...)
	if err != nil {
		return err
	}

	hello := "localhost"
	var hostErr error
	hostname.Do(func() {
		var err error
		hello, err = os.Hostname()
		if err != nil {
			hostErr = err
		}
	})
	if hostErr != nil {
		return fmt.Errorf("senderDirect.send: getting hostname: %w", hostErr)
	}

	groupedTo := make(map[string][]string)
	for _, t := range to {
		d := t[strings.LastIndex(t, "@")+1:]
		groupedTo[d] = append(groupedTo[d], t)
	}

	for domain, t := range groupedTo {
		// Run in goroutine and wait.
		func(t []string) {
			for _, h := range s.getMX(domain) {
				err := s.mail(h, hello, from.Address, t, msg)
				if err != nil {
					var softErr *softError
					if errors.As(err, &softErr) {
						continue
					}
				}

				// Either a hard error or we sent successfully.
				break
			}
		}(t)
	}
	return nil
}

func (s mailerSMTP) mail(host, hello, from string, to []string, msg []byte) error {
	c, err := smtp.Dial(host + ":25")
	if err != nil {
		// Blocked as spam is a fatal errorr; don't try again.
		//
		// 14:52:24 ERROR: 554 5.7.1 Service unavailable; Client host [xxx.xxx.xx.xx] blocked using
		// xbl.spamhaus.org.rbl.local; https://www.spamhaus.org/query/ip/xxx.xxx.xx.xx
		if strings.Contains(err.Error(), " blocked ") {
			return err
		}

		// Can't connect: try next MX
		return softError{err}
	}
	defer c.Close()

	err = c.Hello(hello)
	if err != nil {
		return err

		// Errors from here on are probably fatal error, so just
		// abort.
		// TODO: could improve by checking the status code, but
		// net/smtp doesn't provide them in a good way. This is fine
		// for now as it's intended as a simple backup solution.
		//break
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		err := c.StartTLS(&tls.Config{ServerName: host})
		if err != nil {
			return err
		}
	}

	err = c.Mail(from, nil) // TODO: Add opt.
	if err != nil {
		return err
	}
	// TODO: group by domains.
	for _, addr := range to {
		err = c.Rcpt(addr)
		if err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	err = c.Quit()
	if err != nil {
		return err
	}

	return nil
}

// TODO: cache for same domains.
func (s mailerSMTP) getMX(domain string) []string {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return []string{domain}
	}

	hosts := make([]string, len(mxs))
	for i := range mxs {
		hosts[i] = mxs[i].Host
	}
	return hosts
}

type softError struct{ err error }

func (f softError) Error() string { return f.err.Error() }
func (f softError) Unwrap() error { return f.err }
