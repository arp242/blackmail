package blackmail

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"

	"zgo.at/blackmail/smtp"
)

type testServer struct {
	addr string
	Auth string
}

func newTestServer(t *testing.T, replies map[string]func(*testing.T, net.Conn, string)) *testServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { l.Close() })

	srv := &testServer{addr: l.Addr().String()}
	go func() {
		c, err := l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()

		fmt.Fprintf(c, "220 127.0.0.1 ESMTP ready\r\n")
		var (
			s                     = bufio.NewScanner(c)
			indata, readLoginPass bool
		)
	outer:
		for s.Scan() {
			l := s.Text()

			switch {
			case indata:
				if l == "." {
					fmt.Fprint(c, "250 Ok\r\n")
					indata = false
				}
			case readLoginPass:
				readLoginPass = false
				fmt.Fprint(c, "235 Ok\r\n")
			case strings.HasPrefix(l, "EHLO "):
				fmt.Fprint(c, "250-127.0.0.1\r\n")
				//fmt.Fprint(c, "250-STARTTLS\r\n")
				if srv.Auth != "" {
					fmt.Fprint(c, "250 AUTH LOGIN\r\n")
				} else {
					fmt.Fprint(c, "250 Ok\r\n")
				}
			case strings.HasPrefix(l, "MAIL FROM:"):
				fmt.Fprint(c, "250 Ok\r\n")
			case strings.HasPrefix(l, "RCPT TO:"):
				fmt.Fprint(c, "250 Ok\r\n")
			case strings.HasPrefix(l, "AUTH LOGIN"):
				fmt.Fprint(c, "334 UGFzc3dvcmQ6\r\n")
				readLoginPass = true
			case l == "DATA":
				fmt.Fprint(c, "354 End data with <CR><LF>.<CR><LF>\r\n")
				indata = true
			case l == "QUIT":
				fmt.Fprint(c, "221 bye\r\n")
				c.Close()
			default:
				for m, r := range replies {
					if strings.HasPrefix(l, m) {
						r(t, c, l)
						continue outer
					}
				}
				t.Errorf("unrecognized command: %q", l)
				return
			}
		}
	}()

	return srv
}

func (t testServer) Addr() string {
	if t.Auth != "" {
		return "smtp://" + t.Auth + "@" + t.addr
	}
	return "smtp://" + t.addr
}

var normalizeRepl = strings.NewReplacer("\t", "", "\n", "\r\n")

func normalize(s string) string {
	return normalizeRepl.Replace(strings.TrimLeft(s, "\n"))
}

func TestMailerRelay(t *testing.T) {
	tests := []struct {
		name string
		srv  *testServer
		want string
	}{
		{"basic", newTestServer(t, nil), normalize(`
			SERVER  220 127.0.0.1 ESMTP ready
			CLIENT  EHLO localhost
			SERVER  250-127.0.0.1
			SERVER  250 Ok
			CLIENT  MAIL FROM:<myemail@example.com>
			SERVER  250 Ok
			CLIENT  RCPT TO:<to@example.com>
			SERVER  250 Ok
			CLIENT  DATA
			SERVER  354 End data with <CR><LF>.<CR><LF>
			CLIENT  From: "My name" <myemail@example.com>
			CLIENT  To: <to@example.com>
			CLIENT  Message-Id: <blackmail-20190618133700.1234-16@example.com>
			CLIENT  Date: Tue, 18 Jun 2019 13:37:00 +0000
			CLIENT  Subject: Subject!
			CLIENT  Content-Type: text/plain; charset=utf-8
			CLIENT  Content-Transfer-Encoding: quoted-printable
			CLIENT  
			CLIENT  Well, hello there!
			CLIENT  .
			SERVER  250 Ok
		`)},
		{"auth", func() *testServer { srv := newTestServer(t, nil); srv.Auth = "test@example.com:secret"; return srv }(), normalize(`
			SERVER  220 127.0.0.1 ESMTP ready
			CLIENT  EHLO localhost
			SERVER  250-127.0.0.1
			SERVER  250 AUTH LOGIN
			CLIENT  AUTH LOGIN dGVzdEBleGFtcGxlLmNvbQ==
			SERVER  334 UGFzc3dvcmQ6
			CLIENT  c2VjcmV0
			SERVER  235 Ok
			CLIENT  MAIL FROM:<myemail@example.com>
			SERVER  250 Ok
			CLIENT  RCPT TO:<to@example.com>
			SERVER  250 Ok
			CLIENT  DATA
			SERVER  354 End data with <CR><LF>.<CR><LF>
			CLIENT  From: "My name" <myemail@example.com>
			CLIENT  To: <to@example.com>
			CLIENT  Message-Id: <blackmail-20190618133700.1234-16@example.com>
			CLIENT  Date: Tue, 18 Jun 2019 13:37:00 +0000
			CLIENT  Subject: Subject!
			CLIENT  Content-Type: text/plain; charset=utf-8
			CLIENT  Content-Transfer-Encoding: quoted-printable
			CLIENT  
			CLIENT  Well, hello there!
			CLIENT  .
			SERVER  250 Ok
		`)},

		//{"starttls", func() *testServer { srv := newTestServer(t, nil); return srv }(), normalize(`
		//	SERVER  220 127.0.0.1 ESMTP ready
		//	CLIENT  EHLO localhost
		//	SERVER  250-127.0.0.1
		//	SERVER  250-STARTTLS
		//	SERVER  250 Ok
		//	CLIENT  MAIL FROM:<myemail@example.com>
		//	SERVER  250 Ok
		//	CLIENT  RCPT TO:<to@example.com>
		//	SERVER  250 Ok
		//	CLIENT  DATA
		//	SERVER  354 End data with <CR><LF>.<CR><LF>
		//	CLIENT  From: "My name" <myemail@example.com>
		//	CLIENT  To: <to@example.com>
		//	CLIENT  Message-Id: <blackmail-20190618133700.1234-16@example.com>
		//	CLIENT  Date: Tue, 18 Jun 2019 13:37:00 +0000
		//	CLIENT  Subject: Subject!
		//	CLIENT  Content-Type: text/plain; charset=utf-8
		//	CLIENT  Content-Transfer-Encoding: quoted-printable
		//	CLIENT
		//	CLIENT  Well, hello there!
		//	CLIENT  .
		//	SERVER  250 Ok
		//`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			have := new(bytes.Buffer)
			m, err := NewRelay(tt.srv.Addr(), &RelayOptions{
				Debug: have,
				Auth:  smtp.AuthLogin,
				TLS:   &tls.Config{},
			})
			if err != nil {
				t.Fatal(err)
			}

			err = m.Send("Subject!",
				From("My name", "myemail@example.com"),
				To("to@example.com"),
				Bodyf("Well, hello there!"))
			if err != nil {
				t.Fatal(err)
			}

			if have.String() != tt.want {
				t.Errorf("\nhave:\n%s\nwant:\n%s\n\n%[1]q\n%[2]q", have, tt.want)
			}
		})
	}
}
