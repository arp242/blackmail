// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"zgo.at/zstd/ztest"
)

func TestBasic(t *testing.T) {
	var buf bytes.Buffer
	cmdbuf := bufio.NewWriter(&buf)

	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(bs(`
		250 mx.google.com at your service
		502 Unrecognized command.
		250-mx.google.com at your service
		250-SIZE 35651584
		250-AUTH LOGIN PLAIN
		250 8BITMIME
		530 Authentication required
		252 Send some mail, I'll try my best
		250 User is valid
		235 Accepted
		250 Sender OK
		250 Receiver OK
		354 Go ahead
		250 Data OK
		221 OK
	`))), cmdbuf)

	c := &Client{Text: textproto.NewConn(fake), localName: "localhost"}

	if err := c.helo(); err != nil {
		t.Fatalf("HELO failed: %s", err)
	}
	if err := c.ehlo(); err == nil {
		t.Fatalf("Expected first EHLO to fail")
	}
	if err := c.ehlo(); err != nil {
		t.Fatalf("Second EHLO failed: %s", err)
	}

	c.didHello = true
	if ok, args := c.Extension("aUtH"); !ok || args != "LOGIN PLAIN" {
		t.Fatalf("Expected AUTH supported")
	}
	if ok, _ := c.Extension("DSN"); ok {
		t.Fatalf("Shouldn't support DSN")
	}

	if err := c.Mail("user@gmail.com"); err == nil {
		t.Fatalf("MAIL should require authentication")
	}

	if err := c.Verify("user1@gmail.com"); err == nil {
		t.Fatalf("First VRFY: expected no verification")
	}
	if err := c.Verify("user2@gmail.com>\r\nDATA\r\nAnother injected message body\r\n.\r\nQUIT\r\n"); err == nil {
		t.Fatalf("VRFY should have failed due to a message injection attempt")
	}
	if err := c.Verify("user2@gmail.com"); err != nil {
		t.Fatalf("Second VRFY: expected verification, got %s", err)
	}

	// fake TLS so authentication won't complain
	c.tls = true
	c.serverName = "smtp.google.com"
	if err := c.Auth(PlainAuth("", "user", "pass")); err != nil {
		t.Fatalf("AUTH failed: %s", err)
	}

	if err := c.Rcpt("golang-nuts@googlegroups.com>\r\nDATA\r\nInjected message body\r\n.\r\nQUIT\r\n"); err == nil {
		t.Fatalf("RCPT should have failed due to a message injection attempt")
	}
	if err := c.Mail("user@gmail.com>\r\nDATA\r\nAnother injected message body\r\n.\r\nQUIT\r\n"); err == nil {
		t.Fatalf("MAIL should have failed due to a message injection attempt")
	}
	if err := c.Mail("user@gmail.com"); err != nil {
		t.Fatalf("MAIL failed: %s", err)
	}
	if err := c.Rcpt("golang-nuts@googlegroups.com"); err != nil {
		t.Fatalf("RCPT failed: %s", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA failed: %s", err)
	}
	_, err = w.Write(bb(`
		From: user@gmail.com
		To: golang-nuts@googlegroups.com
		Subject: Hooray for Go

		Line 1
		.Leading dot line .
		Goodbye.`))
	if err != nil {
		t.Fatalf("Data write failed: %s", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Bad data response: %s", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %s", err)
	}

	cmdbuf.Flush()

	want := bs(`
		HELO localhost
		EHLO localhost
		EHLO localhost
		MAIL FROM:<user@gmail.com> BODY=8BITMIME
		VRFY user1@gmail.com
		VRFY user2@gmail.com
		AUTH PLAIN AHVzZXIAcGFzcw==
		MAIL FROM:<user@gmail.com> BODY=8BITMIME
		RCPT TO:<golang-nuts@googlegroups.com>
		DATA
		From: user@gmail.com
		To: golang-nuts@googlegroups.com
		Subject: Hooray for Go

		Line 1
		..Leading dot line .
		Goodbye.
		.
		QUIT`)
	if d := ztest.Diff(buf.String(), want); d != "" {
		t.Error(d)
	}
}

func TestBasic_SMTPError(t *testing.T) {
	// RFC 2034 says that enhanced codes *SHOULD* be included in errors,
	// this means it can be violated hence we need to handle last
	// case properly.
	var wrote bytes.Buffer
	var fake faker
	fake.ReadWriter = struct {
		io.Reader
		io.Writer
	}{strings.NewReader(bs(`
		220 mx.google.com at your service
		250-mx.google.com at your service
		250 ENHANCEDSTATUSCODES
		500 5.0.0 Failing with enhanced code
		500 Failing without enhanced code
	`)), &wrote}
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	err = c.Mail("whatever")
	if err == nil {
		t.Fatal("MAIL succeded")
	}
	smtpErr, ok := err.(*SMTPError)
	if !ok {
		t.Fatal("Returned error is not SMTPError")
	}
	if smtpErr.Code != 500 {
		t.Fatalf("Wrong status code, got %d, want %d", smtpErr.Code, 500)
	}
	if smtpErr.EnhancedCode != (EnhancedCode{5, 0, 0}) {
		t.Fatalf("Wrong enhanced code, got %v, want %v", smtpErr.EnhancedCode, EnhancedCode{5, 0, 0})
	}
	if smtpErr.Message != "Failing with enhanced code" {
		t.Fatalf("Wrong message, got %s, want %s", smtpErr.Message, "Failing with enhanced code")
	}

	err = c.Mail("whatever")
	if err == nil {
		t.Fatal("MAIL succeded")
	}
	smtpErr, ok = err.(*SMTPError)
	if !ok {
		t.Fatal("Returned error is not SMTPError")
	}
	if smtpErr.Code != 500 {
		t.Fatalf("Wrong status code, got %d, want %d", smtpErr.Code, 500)
	}
	if smtpErr.Message != "Failing without enhanced code" {
		t.Fatalf("Wrong message, got %s, want %s", smtpErr.Message, "Failing without enhanced code")
	}
}

func TestNewClient(t *testing.T) {
	var buf bytes.Buffer
	cmdbuf := bufio.NewWriter(&buf)
	out := func() string {
		cmdbuf.Flush()
		return buf.String()
	}

	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(bs(`
		220 hello world
		250-mx.google.com at your service
		250-SIZE 35651584
		250-AUTH LOGIN PLAIN
		250 8BITMIME
		221 OK
	`))), cmdbuf)
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v\n(after %v)", err, out())
	}
	defer c.Close()

	if ok, args := c.Extension("aUtH"); !ok || args != "LOGIN PLAIN" {
		t.Fatalf("Expected AUTH supported")
	}
	if ok, _ := c.Extension("DSN"); ok {
		t.Fatalf("Shouldn't support DSN")
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %s", err)
	}

	want := bs(`
		EHLO localhost
		QUIT`)
	if d := ztest.Diff(out(), want); d != "" {
		t.Error(d)
	}
}

func TestNewClient2(t *testing.T) {
	var buf bytes.Buffer
	cmdbuf := bufio.NewWriter(&buf)
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(bs(`
		220 hello world
		502 EH?
		250-mx.google.com at your service
		250-SIZE 35651584
		250-AUTH LOGIN PLAIN
		250 8BITMIME
		221 OK
	`))), cmdbuf)

	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("DSN"); ok {
		t.Fatalf("Shouldn't support DSN")
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %s", err)
	}

	cmdbuf.Flush()

	want := bs(`
		EHLO localhost
		HELO localhost
		QUIT`)
	if d := ztest.Diff(buf.String(), want); d != "" {
		t.Error(d)
	}
}

// TODO: rewrite to a loop.
func TestHello(t *testing.T) {
	var baseHelloServer = `220 hello world
502 EH?
250-mx.google.com at your service
250 FEATURE
`

	var baseHelloClient = `EHLO customhost
HELO customhost
`

	var helloClient = []string{
		"",
		"STARTTLS\n",
		"VRFY test@example.com\n",
		"AUTH PLAIN AHVzZXIAcGFzcw==\n",
		"MAIL FROM:<test@example.com>\n",
		"",
		"RSET\n",
		"QUIT\n",
		"VRFY test@example.com\n",
		"NOOP\n",
	}

	var helloServer = []string{
		"",
		"502 Not implemented\n",
		"250 User is valid\n",
		"235 Accepted\n",
		"250 Sender ok\n",
		"",
		"250 Reset ok\n",
		"221 Goodbye\n",
		"250 Sender ok\n",
		"250 ok\n",
	}

	if len(helloServer) != len(helloClient) {
		t.Fatalf("Hello server and client size mismatch")
	}

	for i := 0; i < len(helloServer); i++ {
		server := strings.Join(strings.Split(baseHelloServer+helloServer[i], "\n"), "\r\n")
		client := strings.Join(strings.Split(baseHelloClient+helloClient[i], "\n"), "\r\n")

		var buf bytes.Buffer
		cmdbuf := bufio.NewWriter(&buf)
		var fake faker
		fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), cmdbuf)
		c, err := NewClient(fake, "fake.host")
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer c.Close()
		c.localName = "customhost"
		err = nil

		switch i {
		case 0:
			err = c.Hello("hostinjection>\n\rDATA\r\nInjected message body\r\n.\r\nQUIT\r\n")
			if err == nil {
				t.Errorf("Expected Hello to be rejected due to a message injection attempt")
			}
			err = c.Hello("customhost")
		case 1:
			err = c.StartTLS(nil)
			if err.Error() == "Not implemented" {
				err = nil
			}
		case 2:
			err = c.Verify("test@example.com")
		case 3:
			c.tls = true
			c.serverName = "smtp.google.com"
			err = c.Auth(PlainAuth("", "user", "pass"))
		case 4:
			err = c.Mail("test@example.com")
		case 5:
			ok, _ := c.Extension("feature")
			if ok {
				t.Errorf("Expected FEATURE not to be supported")
			}
		case 6:
			err = c.Reset()
		case 7:
			err = c.Quit()
		case 8:
			err = c.Verify("test@example.com")
			if err != nil {
				err = c.Hello("customhost")
				if err != nil {
					t.Errorf("Want error, got none")
				}
			}
		case 9:
			err = c.Noop()
		default:
			t.Fatalf("Unhandled command")
		}

		if err != nil {
			t.Errorf("Command %d failed: %v", i, err)
		}

		cmdbuf.Flush()
		actualcmds := buf.String()
		if client != actualcmds {
			t.Errorf("Got:\n%s\nExpected:\n%s", actualcmds, client)
		}
	}
}

func TestSend(t *testing.T) {
	var buf bytes.Buffer
	cmdbuf := bufio.NewWriter(&buf)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to create listener: %v", err)
	}
	defer l.Close()

	// prevent data race on cmdbuf
	var done = make(chan struct{})
	go func(data []string) {
		defer close(done)

		conn, err := l.Accept()
		if err != nil {
			t.Errorf("Accept error: %v", err)
			return
		}
		defer conn.Close()

		tc := textproto.NewConn(conn)
		for i := 0; i < len(data) && data[i] != ""; i++ {
			tc.PrintfLine(data[i])
			for len(data[i]) >= 4 && data[i][3] == '-' {
				i++
				tc.PrintfLine(data[i])
			}
			if data[i] == "221 Goodbye" {
				return
			}
			read := false
			for !read || data[i] == "354 Go ahead" {
				msg, err := tc.ReadLine()
				cmdbuf.Write([]byte(msg + "\r\n"))
				read = true
				if err != nil {
					t.Errorf("Read error: %v", err)
					return
				}
				if data[i] == "354 Go ahead" && msg == "." {
					break
				}
			}
		}
	}(strings.Split(bs(`
		220 hello world
		502 EH?
		250 mx.google.com at your service
		250 Sender ok
		250 Receiver ok
		354 Go ahead
		250 Data ok
		221 Goodbye
	`), "\r\n"))

	err = Send(l.Addr().String(), "test@example.com", []string{"other@example.com>\n\rDATA\r\nInjected message body\r\n.\r\nQUIT\r\n"}, bb(`
		To: other@example.com
		Subject: SendMail test
		SendMail is working for me.`))
	if err == nil {
		t.Errorf("Expected SendMail to be rejected due to a message injection attempt")
	}

	err = Send(l.Addr().String(), "test@example.com", []string{"other@example.com"}, bb(`
		From: test@example.com
		To: other@example.com
		Subject: SendMail test

		SendMail is working for me.`))
	if err != nil {
		t.Errorf("%v", err)
	}

	<-done
	cmdbuf.Flush()

	want := bs(`
		EHLO localhost
		HELO localhost
		MAIL FROM:<test@example.com>
		RCPT TO:<other@example.com>
		DATA
		From: test@example.com
		To: other@example.com
		Subject: SendMail test

		SendMail is working for me.
		.
		QUIT`)
	if d := ztest.Diff(buf.String(), want); d != "" {
		t.Errorf(d)
	}
}

func TestSendWithAuth(t *testing.T) {
	t.Skip() // TODO: hangs?

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to create listener: %v", err)
	}
	defer l.Close()

	wg := sync.WaitGroup{}
	wg.Add(1)

	var done = make(chan struct{})
	go func() {
		defer wg.Done()

		conn, err := l.Accept()
		if err != nil {
			t.Errorf("Accept error: %v", err)
			return
		}
		defer conn.Close()

		tc := textproto.NewConn(conn)
		tc.PrintfLine("220 hello world")
		msg, err := tc.ReadLine()
		if err != nil {
			t.Error(err)
			return
		}
		if msg == "EHLO localhost" {
			tc.PrintfLine("250 mx.google.com at your service")
		}

		<-done // for this test case, there should have no more traffic
	}()

	err = Send(l.Addr().String(), "test@example.com", []string{"other@example.com"}, bb(`
		From: test@example.com
		To: other@example.com
		Subject: SendMail test
		SendMail is working for me.
	`), SendAuth(PlainAuth("", "user", "pass")))
	if err == nil {
		t.Error("SendMail: Server doesn't support AUTH, expected to get an error, but got none ")
	}
	if err.Error() != "smtp: server doesn't support AUTH" {
		t.Errorf("Expected: smtp: server doesn't support AUTH, got: %s", err)
	}
	close(done)
	wg.Wait()
}

func TestAuthFailed(t *testing.T) {
	var buf bytes.Buffer
	cmdbuf := bufio.NewWriter(&buf)
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(bs(`
		220 hello world
		250-mx.google.com at your service
		250 AUTH LOGIN PLAIN
		535-Invalid credentials
		535 please see www.example.com
		221 Goodbye
	`))), cmdbuf)

	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	c.tls = true
	c.serverName = "smtp.google.com"
	err = c.Auth(PlainAuth("", "user", "pass"))

	if err == nil {
		t.Error("Auth: expected error; got none")
	} else if err.Error() != "Invalid credentials\nplease see www.example.com" {
		t.Errorf("Auth: got error: %v, want: %s", err, "Invalid credentials\nplease see www.example.com")
	}

	cmdbuf.Flush()

	want := bs(`
		EHLO localhost
		AUTH PLAIN AHVzZXIAcGFzcw==
		*`)
	if d := ztest.Diff(buf.String(), want); d != "" {
		t.Errorf(d)
	}
}

func TestTLSClient(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	errc := make(chan error)
	go func() {
		errc <- Send(ln.Addr().String(), "joe1@example.com", []string{"joe2@example.com"}, []byte("Subject: test\n\nhowdy!"))
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("failed to accept connection: %v", err)
	}
	defer conn.Close()

	if err := serverHandle(conn, t); err != nil {
		t.Fatalf("failed to handle connection: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestTLSConnState(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()
	clientDone := make(chan bool)
	serverDone := make(chan bool)

	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer c.Close()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()

	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer c.Quit()
		cfg := &tls.Config{ServerName: "example.com"}
		testHookStartTLS(cfg) // set the RootCAs
		if err := c.StartTLS(cfg); err != nil {
			t.Errorf("StartTLS: %v", err)
			return
		}
		cs, ok := c.TLSConnectionState()
		if !ok {
			t.Errorf("TLSConnectionState returned ok == false; want true")
			return
		}
		if cs.Version == 0 || !cs.HandshakeComplete {
			t.Errorf("ConnectionState = %#v; expect non-zero Version and HandshakeComplete", cs)
		}
	}()
	<-clientDone
	<-serverDone
}

// toServerEmptyAuth is an implementation of Auth that only implements
// the Start method, and returns "FOOAUTH", nil, nil. Notably, it returns
// zero bytes for "toServer" so we can test that we don't send spaces at
// the end of the line. See TestClientAuthTrimSpace.
type toServerEmptyAuth struct{}

func (toServerEmptyAuth) Start() (proto string, toServer []byte, err error) {
	return "FOOAUTH", nil, nil
}
func (toServerEmptyAuth) Next(fromServer []byte) (toServer []byte, err error) {
	panic("unexpected call")
}

// Issue 17794: don't send a trailing space on AUTH command when there's no password.
func TestClientAuthTrimSpace(t *testing.T) {
	var wrote bytes.Buffer
	var fake faker
	fake.ReadWriter = struct {
		io.Reader
		io.Writer
	}{strings.NewReader("220 hello world\r\n200 some more"), &wrote}

	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	c.tls = true
	c.didHello = true
	c.Auth(toServerEmptyAuth{})
	c.Close()
	if have, want := wrote.String(), "AUTH FOOAUTH\r\n*\r\n"; have != want {
		t.Errorf("wrote %q; want %q", have, want)
	}
}
