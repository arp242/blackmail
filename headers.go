package blackmail

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/textproto"
	"strings"
)

// The HeaderPart contains an ordered list of headers.
type HeaderPart struct {
	err     error
	headers [][2]string
}

func (HeaderPart) blackmail()       {}
func (p HeaderPart) Error() error   { return p.err }
func (p HeaderPart) String() string { return fmt.Sprintf("%v", p.headers) }

// Remove the header and return the value. Returns "" if the header wasn't set.
func (p *HeaderPart) Remove(name string) string {
	if p == nil {
		return ""
	}
	name = textproto.CanonicalMIMEHeaderKey(name)
	for i := range p.headers {
		if p.headers[i][0] == name {
			v := p.headers[i][1]
			p.headers = append(p.headers[:i], p.headers[i+1:]...)
			return v
		}
	}
	return ""
}

// Append another header part to this one.
func (p *HeaderPart) Append(parts ...HeaderPart) {
	for _, pp := range parts {
		if pp.err != nil {
			p.err = pp.err
		}
		p.headers = append(p.headers, pp.headers...)
	}
}

// Write all headers.
func (p HeaderPart) Write(w io.Writer) {
	for _, h := range p.headers {
		w.Write([]byte(h[0]))
		w.Write([]byte(": "))
		w.Write([]byte(mime.QEncoding.Encode("utf-8", h[1])))
		w.Write([]byte("\r\n"))
	}
}

// WriteDefault writes a header to w; this prefers using the value in this
// header part if it exists, falling back to value if it doesn't.
//
// The value will be removed from the HeaderPart when written.
func (p *HeaderPart) WriteDefault(w io.Writer, key, value string) {
	key = textproto.CanonicalMIMEHeaderKey(key)
	v := p.Remove(key)
	if v == "" {
		v = value
	}

	w.Write([]byte(key))
	w.Write([]byte(": "))
	w.Write([]byte(mime.QEncoding.Encode("utf-8", v)))
	w.Write([]byte("\r\n"))
}

func (p HeaderPart) FromList(list []string) HeaderPart {
	if len(list)%2 == 1 {
		return HeaderPart{err: errors.New("blackmail.Headers: odd argument count")}
	}

	for i := range list {
		if i%2 == 0 {
			p.headers = append(p.headers, [2]string{
				textproto.CanonicalMIMEHeaderKey(list[i]),
				list[i+1]})
		}
	}
	return p
}

func (p HeaderPart) FromKV(split rune, keyValue ...string) HeaderPart {
	for _, kv := range keyValue {
		sp := strings.SplitN(kv, string(split), 2)
		if len(sp) != 2 {
			p.err = fmt.Errorf("missing %s in %q", string(split), kv)
		}
		p.headers = append(p.headers, [2]string{sp[0], sp[1]})
	}
	return p
}
