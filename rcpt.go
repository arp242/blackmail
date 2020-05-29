package blackmail

import (
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
)

const (
	rcptTo  = "to"
	rcptCc  = "cc"
	rcptBcc = "bcc"
)

// rcpt is someone to send an email to. Create a new one with the To*, Cc(), or
// Bcc() functions.
type RcptPart struct {
	err error

	kind string // to, cc, bcc
	mail.Address
}

func (RcptPart) blackmail()       {}
func (p RcptPart) Error() error   { return p.err }
func (p RcptPart) String() string { return p.kind + ": " + p.Name + "<" + p.Address.Address + ">" }

type RcptParts []RcptPart

func (RcptParts) blackmail()   {}
func (RcptParts) Error() error { return nil }

// TODO: much of the below should be methods.

func writeRcpt(w io.Writer, key string, addr ...mail.Address) {
	if len(addr) == 0 {
		return
	}
	fmt.Fprintf(w, "%s: ", textproto.CanonicalMIMEHeaderKey(key))
	for i, a := range addr {
		fmt.Fprint(w, a.String())
		if i != len(addr)-1 {
			w.Write([]byte(", "))
		}
	}
	w.Write([]byte("\r\n"))
}

func rcptOne(k, n, a string) RcptPart {
	return RcptPart{kind: k, Address: mail.Address{Name: n, Address: a}}
}

func rcptNames(kind string, nameAddr []string) []RcptPart {
	if len(nameAddr)%2 == 1 {
		return []RcptPart{{err: errors.New("odd argument count")}}
	}

	r := make([]RcptPart, len(nameAddr)/2)
	for i := range nameAddr {
		if i%2 == 1 {
			continue
		}
		r[i/2] = RcptPart{kind: kind, Address: mail.Address{Name: nameAddr[i], Address: nameAddr[i+1]}}
	}
	return r
}

func rcptAddr(kind string, addr []mail.Address) []RcptPart {
	r := make([]RcptPart, len(addr))
	for i := range addr {
		r[i] = RcptPart{kind: kind, Address: addr[i]}
	}
	return r
}

func rcptList(kind string, addr []string) []RcptPart {
	r := make([]RcptPart, len(addr))
	for i := range addr {
		r[i] = RcptPart{kind: kind, Address: mail.Address{Address: addr[i]}}
	}
	return r
}
