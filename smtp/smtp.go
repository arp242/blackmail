// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package smtp implements a SMTP client as defined in RFC 5321.
//
// It also implements the following extensions:
//
//  8BITMIME             RFC 1652
//  ENHANCEDSTATUSCODES  RFC 2034
//  STARTTLS             RFC 3207
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

// Debug prints all outgoing and incoming messages to stderr.
var Debug = false

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
	// Text is the textproto.Conn used by the Client. It is exported to allow
	// clients to add extensions.
	Text *textproto.Conn

	conn       net.Conn          // So it can be used to create a TLS connection later.
	tls        bool              // TLS enabled?
	serverName string            // TLS servername.
	ext        map[string]string // Map of supported extensions.
	auth       []string          // Supported auth mechanisms.
	localName  string            // The name to use in HELO/EHLO/LHLO
	didHello   bool              // Whether we've said HELO/EHLO/LHLO
	helloError error             // The error from the hello.
	rcpts      []string          // Recipients accumulated for the current session.
}

func SendAuth(v Auth) sendOpt                 { return func(c *sendOptions) { c.auth = v } }
func SendTLS(v *tls.Config) sendOpt           { return func(c *sendOptions) { c.tls = v } }
func SendRequireTLS(v bool) sendOpt           { return func(c *sendOptions) { c.tlsRequired = v } }
func SendMailOptions(opts ...mailOpt) sendOpt { return func(c *sendOptions) { c.mailOptions = opts } }

// Send is a high-level API to send an email.
//
// The addr can include a port (e.g. "mail.example.com:465") and will default to
// 25 if omitted.
//
// The addresses in the to parameter are the SMTP RCPT addresses.
//
// The msg parameter should be an CRLF terminated RFC 5322-style email with
// headers, as created by blackmail.Message()
//
// Note: sending "Bcc" messages is accomplished by including the email address
// in the to parameter but not including it in the msg headers.
func Send(addr string, from string, to []string, msg []byte, opts ...sendOpt) error {
	return send(addr, from, to, msg, opts...)
}

// Dial returns a new Client connected to an SMTP server at addr.
//
// The addr must include a port, as in "mail.example.com:smtp" or
// "mail.example.com:465".
func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewClient(conn, addr)
}

// DialTLS returns a new Client connected to an SMTP server via TLS at addr.
//
// The addr must include a port, as in "mail.example.com:smtp" or
// "mail.example.com:465".
func DialTLS(addr string, tlsConfig *tls.Config) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	return NewClient(conn, addr)
}

// NewClient returns a new Client using an existing connection and host as a
// server name, which is used when authenticating.
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
	host, _, _ = net.SplitHostPort(host)
	return &Client{
		Text:       text,
		conn:       conn,
		serverName: host,
		localName:  "localhost",
		tls:        isTLS,
	}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.Text.Close()
}

// Hello sends a HELO or EHLO to the server as the given host name.
//
// Calling this method is only necessary if the client needs control over the
// host name used. The client will introduce itself as "localhost" automatically
// otherwise. If Hello is called, it must be called before any of the other
// methods.
//
// Server errors are returned as *SMTPError.
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

// StartTLS sends the STARTTLS command and encrypts all further communication.
//
// Only servers that advertise the STARTTLS extension support this function.
//
// Server errors are returned as *SMTPError.
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
		config = config.Clone() // Copy to avoid modifying the argument.
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

// TLSConnectionState returns the client's TLS connection state. The return
// values are their zero values if StartTLS did not succeed.
func (c *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// Verify checks the validity of an email address on the server.
//
// If Verify returns nil, the address is valid. A non-nil return does not
// necessarily indicate an invalid address; many servers will not verify
// addresses for security reasons.
//
// Server errors are returned as *SMTPError.
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
//
// Only servers that advertise the AUTH extension support this function.
//
// Server errors are returned as *SMTPError.
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
		case 235: // the last message isn't base64 because it isn't a challenge
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
		if err != nil { // abort the AUTH
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

// MailSize sets the size of the body; used by servers to reject messages
// quickly if they're too large. Note this should be the total size after
// application of base64 etc. See RFC1870
func MailSize(s int) mailOpt { return func(c *mailOptions) { c.Size = s } }

// The message envelope or message header contains UTF-8-encoded strings. This
// flag is set by SMTPUTF8-aware (RFC 6531) client.
func MailUTF8(enable bool) mailOpt { return func(c *mailOptions) { c.UTF8 = enable } }

// The authorization identity asserted by the message sender in decoded form
// with angle brackets stripped. nil value indicates missing AUTH, non-nil empty
// string indicates AUTH=<>.
// Defined in RFC 4954.
func MailAuth(a string) mailOpt { return func(c *mailOptions) { c.Auth = &a } }

// Mail sends a MAIL command to the server using the provided email address.
//
// BODY=8BITMIME is added if the server supports the 8BITMIME extension.
//
// This initiates a mail transaction and is followed by one or more Rcpt calls.
//
// If opts is not nil, MAIL arguments provided in the structure will be added to
// the command. Handling of unsupported options depends on the extension.
//
// Server errors are returned as *SMTPError.
func (c *Client) Mail(from string, opts ...mailOpt) error {
	if err := validateLine(from); err != nil {
		return err
	}
	if err := c.hello(); err != nil {
		return err
	}

	var opt mailOptions
	for _, o := range opts {
		o(&opt)
	}

	cmd := "MAIL FROM:<%s>"
	if _, ok := c.ext["8BITMIME"]; ok {
		cmd += " BODY=8BITMIME"
	}

	// TODO
	if _, ok := c.ext["SIZE"]; ok && opts != nil && opt.Size != 0 {
		cmd += " SIZE=" + strconv.Itoa(opt.Size)
	}

	// TODO: I don't think we really need this, as we already check it? Need to
	// read doc more:
	// https://tools.ietf.org/html/draft-ietf-uta-smtp-require-tls-09
	//
	// Also check if anyone actually supports that.
	// if opts != nil && opts.RequireTLS {
	// 	if _, ok := c.ext["REQUIRETLS"]; ok {
	// 		cmd += " REQUIRETLS"
	// 	} else {
	// 		return errors.New("smtp: server does not support REQUIRETLS")
	// 	}
	// }

	// TODO: check
	//  SMTPUTF8             RFC 6531
	// if opts != nil && opts.UTF8 {
	// 	if _, ok := c.ext["SMTPUTF8"]; ok {
	// 		cmd += " SMTPUTF8"
	// 	} else {
	// 		return errors.New("smtp: server does not support SMTPUTF8")
	// 	}
	// }

	// TODO: check
	//  AUTH                 RFC 2554
	// if opts != nil && opts.Auth != nil {
	// 	if _, ok := c.ext["AUTH"]; ok {
	// 		cmd += " AUTH=" + encodeXtext(*opts.Auth)
	// 	}
	// 	// We can safely discard parameter if server does not support AUTH.
	// }

	_, _, err := c.cmd(250, cmd, from)
	return err
}

// Rcpt sends a RCPT command to the server.
//
// A call to Rcpt must be preceded by a call to Mail and may be followed by a
// Data call or another Rcpt call.
//
// Server errors are returned as *SMTPError.
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

// Data sends a DATA command to the server, returning a writer to write the
// message to.
//
// The caller should close the writer before calling any more methods on c. A
// call to Data must be preceded by one or more calls to Rcpt.
//
// Server errors are returned as *SMTPError.
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

	param, ok := c.ext[strings.ToUpper(ext)]
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
// If Quit fails the connection is not closed, Close should be used in this
// case.
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
