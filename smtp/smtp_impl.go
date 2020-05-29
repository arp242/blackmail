package smtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
)

type (
	mailOpt     func(*mailOptions)
	mailOptions struct {
		Size int
		UTF8 bool
		Auth *string
	}

	sendOpt     func(*sendOptions)
	sendOptions struct {
		tls         *tls.Config
		tlsRequired bool
		auth        Auth
		mailOptions []mailOpt
	}
)

var testHookStartTLS func(*tls.Config) // nil, except for tests

type dataCloser struct {
	c *Client
	io.WriteCloser
	statusCb func(rcpt string, status *SMTPError)
}

func (d *dataCloser) Close() error {
	d.WriteCloser.Close()
	_, _, err := d.c.Text.ReadResponse(250)
	if err != nil {
		if protoErr, ok := err.(*textproto.Error); ok {
			return toSMTPErr(protoErr)
		}
		return err
	}
	return nil
}

// hello runs a hello exchange if needed.
func (c *Client) hello() error {
	if !c.didHello {
		c.didHello = true
		err := c.ehlo()
		if err != nil {
			c.helloError = c.helo()
		}
	}
	return c.helloError
}

// helo sends the HELO greeting to the server. It should be used only when the
// server does not support ehlo.
func (c *Client) helo() error {
	c.ext = nil
	_, _, err := c.cmd(250, "HELO %s", c.localName)
	return err
}

// ehlo sends the EHLO (extended hello) greeting to the server. It should be the
// preferred greeting for servers that support it.
func (c *Client) ehlo() error {
	_, msg, err := c.cmd(250, "%s %s", "EHLO", c.localName)
	if err != nil {
		return err
	}

	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		c.ext = make(map[string]string)
		for _, line := range extList[1:] {
			args := strings.SplitN(line, " ", 2)
			if len(args) > 1 {
				c.ext[args[0]] = args[1]
			} else {
				c.ext[args[0]] = ""
			}
		}
	}

	if mechs, ok := c.ext["AUTH"]; ok {
		c.auth = strings.Split(mechs, " ")
	}
	return err
}

func send(addr string, from string, to []string, msg []byte, opts ...sendOpt) error {
	if err := validateLine(from); err != nil {
		return err
	}
	for _, recp := range to {
		if err := validateLine(recp); err != nil {
			return err
		}
	}

	opt := &sendOptions{}
	for _, o := range opts {
		o(opt)
	}

	_, port, _ := net.SplitHostPort(addr)
	if port == "" {
		port = "25"
	}

	var (
		c   *Client
		err error
	)
	if port == "465" {
		c, err = DialTLS(addr, opt.tls)
	} else {
		c, err = Dial(addr)
	}
	if err != nil {
		return err
	}
	defer c.Close()

	err = c.hello()
	if err != nil {
		return err
	}

	// STARTTLS
	if !c.tls {
		ok, _ := c.Extension("STARTTLS")
		if !ok && opt.tlsRequired {
			return errors.New("TLS required")
		}
		if ok {
			err = c.StartTLS(nil)
			if err != nil {
				return err
			}
		}
	}

	// AUTH
	if opt.auth != nil && c.ext != nil {
		if _, ok := c.ext["AUTH"]; !ok {
			return errors.New("smtp: server doesn't support AUTH")
		}
		if err = c.Auth(opt.auth); err != nil {
			return err
		}
	}

	err = c.Mail(from, opt.mailOptions...)
	if err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
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
	return c.Quit()
}

func parseEnhancedCode(s string) (EnhancedCode, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return EnhancedCode{}, fmt.Errorf("wrong amount of enhanced code parts")
	}

	code := EnhancedCode{}
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return code, err
		}
		code[i] = num
	}
	return code, nil
}

// toSMTPErr converts textproto.Error into SMTPError, parsing
// enhanced status code if it is present.
func toSMTPErr(protoErr *textproto.Error) *SMTPError {
	if protoErr == nil {
		return nil
	}
	smtpErr := &SMTPError{
		Code:    protoErr.Code,
		Message: protoErr.Msg,
	}

	parts := strings.SplitN(protoErr.Msg, " ", 2)
	if len(parts) != 2 {
		return smtpErr
	}

	enchCode, err := parseEnhancedCode(parts[0])
	if err != nil {
		return smtpErr
	}

	smtpErr.EnhancedCode = enchCode
	smtpErr.Message = parts[1]
	return smtpErr
}

// validateLine checks to see if a line has CR or LF as per RFC 5321.
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}

func encodeXtext(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))

	for _, ch := range raw {
		if ch == '+' || ch == '=' {
			out.WriteRune('+')
			out.WriteString(strings.ToUpper(strconv.FormatInt(int64(ch), 16)))
		}
		if ch > '!' && ch < '~' { // printable non-space US-ASCII
			out.WriteRune(ch)
		}
		// Non-ASCII.
		out.WriteRune('+')
		out.WriteString(strings.ToUpper(strconv.FormatInt(int64(ch), 16)))
	}
	return out.String()
}

// cmd is a convenience function that sends a command and returns the response
// textproto.Error returned by c.Text.ReadResponse is converted into SMTPError.
func (c *Client) cmd(expectCode int, format string, args ...interface{}) (int, string, error) {
	if Debug {
		fmt.Fprintf(os.Stderr, "C: "+format+"\n", args...)
	}

	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)

	if Debug {
		msg = fmt.Sprintf("%d %s", code, msg)
		sm := strings.Split(msg, "\n")
		for i := range sm {
			sm[i] = "S: " + sm[i]
		}
		fmt.Fprintf(os.Stderr, strings.Join(sm, "\n")+"\n")
	}
	if err != nil {
		if protoErr, ok := err.(*textproto.Error); ok {
			smtpErr := toSMTPErr(protoErr)
			return code, smtpErr.Message, smtpErr
		}
		return code, msg, err
	}
	return code, msg, nil
}
