// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package smtp implements a SMTP client as defined in RFC 5321.
//
// It also implements the following extensions:
//
//	8BITMIME             RFC 1652
//	AUTH                 RFC 2554
//	STARTTLS             RFC 3207
//	ENHANCEDSTATUSCODES  RFC 2034
//	SMTPUTF8             RFC 6531
//	REQUIRETLS           draft-ietf-uta-smtp-require-tls-09
package smtp

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
)

// MailOptions contains custom arguments that were passed as an argument to the
// MAIL command.
type MailOptions struct {
	// Size of the body. Can be 0 if not specified by client.
	Size int

	// TLS is required for the message transmission.
	//
	// The message should be rejected if it can't be transmitted
	// with TLS.
	RequireTLS bool

	// The message envelope or message header contains UTF-8-encoded strings.
	// This flag is set by SMTPUTF8-aware (RFC 6531) client.
	UTF8 bool

	// The authorization identity asserted by the message sender in decoded
	// form with angle brackets stripped.
	//
	// nil value indicates missing AUTH, non-nil empty string indicates
	// AUTH=<>.
	//
	// Defined in RFC 4954.
	Auth *string
}

type EnhancedCode [3]int

// SMTPError specifies the error code, enhanced error code (if any) and message
// returned by the server.
type SMTPError struct {
	Code         int
	EnhancedCode EnhancedCode
	Message      string
}

func (err *SMTPError) Error() string   { return err.Message }
func (err *SMTPError) Temporary() bool { return err.Code/100 == 4 }

// A Client represents a client connection to an SMTP server.
type Client struct {
	// Text is the textproto.Conn used by the Client. It is exported to allow for
	// clients to add extensions.
	Text *textproto.Conn

	// keep a reference to the connection so it can be used to create a TLS
	// connection later
	conn net.Conn

	// whether the Client is using TLS
	tls        bool
	serverName string
	lmtp       bool

	// map of supported extensions
	ext map[string]string

	// supported auth mechanisms
	auth       []string
	localName  string   // the name to use in HELO/EHLO/LHLO
	didHello   bool     // whether we've said HELO/EHLO/LHLO
	helloError error    // the error from the hello
	rcpts      []string // recipients accumulated for the current session
}

// SendMail connects to the server at addr, switches to TLS if possible,
// authenticates with the optional mechanism a if possible, and then sends an
// email from address from, to addresses to, with message r.
//
// The addr must include a port, as in "mail.example.com:smtp".
//
// The addresses in the to parameter are the SMTP RCPT addresses.
//
// The r parameter should be an RFC 5322-style email with headers first, a blank
// line, and then the message body. The lines of r should be CRLF terminated.
// The r headers should usually include fields such as "From", "To", "Subject",
// and "Cc".  Sending "Bcc" messages is accomplished by including an email
// address in the to parameter but not including it in the r headers.
//
// TODO: this should accept some options.
func SendMail(addr string, a Auth, from string, to []string, r io.Reader) error {
	if err := validateLine(from); err != nil {
		return err
	}
	for _, recp := range to {
		if err := validateLine(recp); err != nil {
			return err
		}
	}

	// TODO: DialTLS() if port is 465.
	c, err := Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.hello(); err != nil {
		return err
	}

	// TODO: add option to make missing STARTLS an error.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(nil); err != nil {
			return err
		}
	}

	if a != nil && c.ext != nil {
		if _, ok := c.ext["AUTH"]; !ok {
			return errors.New("smtp: server doesn't support AUTH")
		}
		if err = c.Auth(a); err != nil {
			return err
		}
	}
	if err = c.Mail(from, nil); err != nil {
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
	_, err = io.Copy(w, r)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}

// Dial returns a new Client connected to an SMTP server at addr. The addr must
// include a port, as in "mail.example.com:smtp".
func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return NewClient(conn, host)
}

// DialTLS returns a new Client connected to an SMTP server via TLS at addr. The
// addr must include a port, as in "mail.example.com:smtps".
func DialTLS(addr string, tlsConfig *tls.Config) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return NewClient(conn, host)
}

// NewClient returns a new Client using an existing connection and host as a
// server name to be used when authenticating.
func NewClient(conn net.Conn, host string) (*Client, error) {
	text := textproto.NewConn(conn)
	_, _, err := text.ReadResponse(220)
	if err != nil {
		text.Close()
		if protoErr, ok := err.(*textproto.Error); ok {
			return nil, toSMTPErr(protoErr)
		}
		return nil, err
	}
	_, isTLS := conn.(*tls.Conn)
	c := &Client{Text: text, conn: conn, serverName: host, localName: "localhost", tls: isTLS}
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.Text.Close()
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

// Hello sends a HELO or EHLO to the server as the given host name.
// Calling this method is only necessary if the client needs control
// over the host name used. The client will introduce itself as "localhost"
// automatically otherwise. If Hello is called, it must be called before
// any of the other methods.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) Hello(localName string) error {
	if err := validateLine(localName); err != nil {
		return err
	}
	if c.didHello {
		return errors.New("smtp: Hello called after other methods")
	}
	c.localName = localName
	return c.hello()
}

// helo sends the HELO greeting to the server. It should be used only when the
// server does not support ehlo.
func (c *Client) helo() error {
	c.ext = nil
	_, _, err := c.cmd(250, "HELO %s", c.localName)
	return err
}

// ehlo sends the EHLO (extended hello) greeting to the server. It
// should be the preferred greeting for servers that support it.
func (c *Client) ehlo() error {
	cmd := "EHLO"
	if c.lmtp {
		cmd = "LHLO"
	}
	_, msg, err := c.cmd(250, "%s %s", cmd, c.localName)
	if err != nil {
		return err
	}
	ext := make(map[string]string)
	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		extList = extList[1:]
		for _, line := range extList {
			args := strings.SplitN(line, " ", 2)
			if len(args) > 1 {
				ext[args[0]] = args[1]
			} else {
				ext[args[0]] = ""
			}
		}
	}
	if mechs, ok := ext["AUTH"]; ok {
		c.auth = strings.Split(mechs, " ")
	}
	c.ext = ext
	return err
}

// StartTLS sends the STARTTLS command and encrypts all further communication.
// Only servers that advertise the STARTTLS extension support this function.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) StartTLS(config *tls.Config) error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(220, "STARTTLS")
	if err != nil {
		return err
	}
	if config == nil {
		config = &tls.Config{}
	}
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument
		config = config.Clone()
		config.ServerName = c.serverName
	}
	if testHookStartTLS != nil {
		testHookStartTLS(config)
	}
	c.conn = tls.Client(c.conn, config)
	c.Text = textproto.NewConn(c.conn)
	c.tls = true
	return c.ehlo()
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if StartTLS did
// not succeed.
func (c *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// Verify checks the validity of an email address on the server.
// If Verify returns nil, the address is valid. A non-nil return
// does not necessarily indicate an invalid address. Many servers
// will not verify addresses for security reasons.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) Verify(addr string) error {
	if err := validateLine(addr); err != nil {
		return err
	}
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(250, "VRFY %s", addr)
	return err
}

// Auth authenticates a client using the provided authentication mechanism.
// Only servers that advertise the AUTH extension support this function.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) Auth(a Auth) error {
	if err := c.hello(); err != nil {
		return err
	}
	encoding := base64.StdEncoding
	mech, resp, err := a.Start()
	if err != nil {
		return err
	}
	resp64 := make([]byte, encoding.EncodedLen(len(resp)))
	encoding.Encode(resp64, resp)
	code, msg64, err := c.cmd(0, strings.TrimSpace(fmt.Sprintf("AUTH %s %s", mech, resp64)))
	for err == nil {
		var msg []byte
		switch code {
		case 334:
			msg, err = encoding.DecodeString(msg64)
		case 235:
			// the last message isn't base64 because it isn't a challenge
			msg = []byte(msg64)
		default:
			err = toSMTPErr(&textproto.Error{Code: code, Msg: msg64})
		}
		if err == nil {
			if code == 334 {
				resp, err = a.Next(msg)
			} else {
				resp = nil
			}
		}
		if err != nil {
			// abort the AUTH
			c.cmd(501, "*")
			break
		}
		if resp == nil {
			break
		}
		resp64 = make([]byte, encoding.EncodedLen(len(resp)))
		encoding.Encode(resp64, resp)
		code, msg64, err = c.cmd(0, string(resp64))
	}
	return err
}

// Mail issues a MAIL command to the server using the provided email address.
// If the server supports the 8BITMIME extension, Mail adds the BODY=8BITMIME
// parameter.
// This initiates a mail transaction and is followed by one or more Rcpt calls.
//
// If opts is not nil, MAIL arguments provided in the structure will be added
// to the command. Handling of unsupported options depends on the extension.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) Mail(from string, opts *MailOptions) error {
	if err := validateLine(from); err != nil {
		return err
	}
	if err := c.hello(); err != nil {
		return err
	}
	cmdStr := "MAIL FROM:<%s>"
	if _, ok := c.ext["8BITMIME"]; ok {
		cmdStr += " BODY=8BITMIME"
	}
	if _, ok := c.ext["SIZE"]; ok && opts != nil && opts.Size != 0 {
		cmdStr += " SIZE=" + strconv.Itoa(opts.Size)
	}
	if opts != nil && opts.RequireTLS {
		if _, ok := c.ext["REQUIRETLS"]; ok {
			cmdStr += " REQUIRETLS"
		} else {
			return errors.New("smtp: server does not support REQUIRETLS")
		}
	}
	if opts != nil && opts.UTF8 {
		if _, ok := c.ext["SMTPUTF8"]; ok {
			cmdStr += " SMTPUTF8"
		} else {
			return errors.New("smtp: server does not support SMTPUTF8")
		}
	}
	if opts != nil && opts.Auth != nil {
		if _, ok := c.ext["AUTH"]; ok {
			cmdStr += " AUTH=" + encodeXtext(*opts.Auth)
		}
		// We can safely discard parameter if server does not support AUTH.
	}
	_, _, err := c.cmd(250, cmdStr, from)
	return err
}

// Rcpt issues a RCPT command to the server using the provided email address.
// A call to Rcpt must be preceded by a call to Mail and may be followed by
// a Data call or another Rcpt call.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) Rcpt(to string) error {
	if err := validateLine(to); err != nil {
		return err
	}
	if _, _, err := c.cmd(25, "RCPT TO:<%s>", to); err != nil {
		return err
	}
	c.rcpts = append(c.rcpts, to)
	return nil
}

// Data issues a DATA command to the server and returns a writer that
// can be used to write the mail headers and body. The caller should
// close the writer before calling any more methods on c. A call to
// Data must be preceded by one or more calls to Rcpt.
//
// If server returns an error, it will be of type *SMTPError.
func (c *Client) Data() (io.WriteCloser, error) {
	_, _, err := c.cmd(354, "DATA")
	if err != nil {
		return nil, err
	}
	return &dataCloser{c, c.Text.DotWriter(), nil}, nil
}

// Extension reports whether an extension is support by the server.
//
// The extension name is case-insensitive. If the extension is supported,
// Extension also returns a string that contains any parameters the server
// specifies for the extension.
func (c *Client) Extension(ext string) (bool, string) {
	if err := c.hello(); err != nil {
		return false, ""
	}
	if c.ext == nil {
		return false, ""
	}
	ext = strings.ToUpper(ext)
	param, ok := c.ext[ext]
	return ok, param
}

// Reset sends the RSET command to the server, aborting the current mail
// transaction.
func (c *Client) Reset() error {
	if err := c.hello(); err != nil {
		return err
	}
	if _, _, err := c.cmd(250, "RSET"); err != nil {
		return err
	}
	c.rcpts = nil
	return nil
}

// Noop sends the NOOP command to the server. It does nothing but check that the
// connection to the server is okay.
func (c *Client) Noop() error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(250, "NOOP")
	return err
}

// Quit sends the QUIT command and closes the connection to the server.
//
// If Quit fails the connection is not closed, Close should be used
// in this case.
func (c *Client) Quit() error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(221, "QUIT")
	if err != nil {
		return err
	}
	return c.Text.Close()
}

// cmd is a convenience function that sends a command and returns the response
// textproto.Error returned by c.Text.ReadResponse is converted into SMTPError.
func (c *Client) cmd(expectCode int, format string, args ...any) (int, string, error) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)
	if err != nil {
		if protoErr, ok := err.(*textproto.Error); ok {
			smtpErr := toSMTPErr(protoErr)
			return code, smtpErr.Message, smtpErr
		}
		return code, msg, err
	}
	return code, msg, nil
}
