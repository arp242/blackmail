package blackmail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"strings"
	"sync"

	"zgo.at/blackmail/smtp"
)

type senderDirect struct {
	tls        *tls.Config
	requireTLS bool
}

var hostname sync.Once

// TODO: use requireStartTLS
// TODO: use tls
func (s senderDirect) send(subject string, from mail.Address, rcpt []recipient, parts ...bodyPart) error {
	panic("WIP")

	msg, to := message(subject, from, rcpt, parts...)

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
					var softErr *SoftError
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

func (s senderDirect) mail(host, hello, from string, to []string, msg []byte) error {
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
		return SoftError{err}
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

	err = c.Mail(from, nil)
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
func (s senderDirect) getMX(domain string) []string {
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

type SoftError struct{ err error }

func (f SoftError) Error() string { return f.err.Error() }
func (f SoftError) Unwrap() error { return f.err }
