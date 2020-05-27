package blackmail

// This file contains everything that's needed to implement blackmail.go

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type (
	// bodyPart defines the body. Create a new one with one of the Body* or
	// Attachment* functions.
	bodyPart struct {
		err          error
		parts        []bodyPart
		ct           string
		body         []byte
		filename     string
		attach       bool
		inlineAttach bool

		headers         []string // For Headers()
		pubkey, privkey []byte   // For Sign()
		cid             string   // Content-ID reference
	}

	// recipient is someone to send an email to. Create a new one with the To*,
	// Cc(), or Bcc() functions.
	recipient struct {
		mail.Address
		kind string // to, cc, bcc
	}
)

// Allow swapping out in tests.
var (
	now                    = func() time.Time { return time.Now() }
	stdout       io.Writer = os.Stdout
	stderr       io.Writer = os.Stderr
	testBoundary           = ""
	testRandom             = func() uint64 {
		r, _ := rand.Int(rand.Reader, big.NewInt(0).SetUint64(999_999))
		return r.Uint64()
	}
)

func message(subject string, from mail.Address, rcpt []recipient, firstPart bodyPart, parts ...bodyPart) ([]byte, []string) {
	parts = append([]bodyPart{firstPart}, parts...)

	// Get the extra headers out of the parts.
	var userHeaders []string
	{
		var np []bodyPart
		for _, p := range parts {
			switch p.ct {
			default:
				np = append(np, p)
			case "HEADERS":
				for i := range p.headers {
					if i%2 == 0 {
						userHeaders = append(userHeaders, []string{
							textproto.CanonicalMIMEHeaderKey(p.headers[i]),
							p.headers[i+1]}...)
					}
				}
			}
		}
		parts = np
	}

	t := now()
	msg := new(bytes.Buffer)

	// Write address headers.
	var toList []string
	{
		writeA(msg, &userHeaders, "From", from)

		var to, cc, bcc []mail.Address
		for _, r := range rcpt {
			toList = append(toList, r.Address.Address)

			switch r.kind {
			case "to":
				to = append(to, r.Address)
			case "cc":
				cc = append(cc, r.Address)
			case "bcc":
				bcc = append(bcc, r.Address)
			default:
				panic(fmt.Sprintf("blackmail.Message: unknown recipient type: %q", r.kind))
			}
		}

		if len(to) > 0 {
			writeA(msg, &userHeaders, "To", to...)
		}
		if len(cc) > 0 {
			writeA(msg, &userHeaders, "Cc", cc...)
		}
		if len(to) == 0 && len(bcc) > 0 {
			writeH(msg, &userHeaders, "To", "undisclosed-recipients:;")
		}
	}

	// Write other headers.
	{
		writeH(msg, &userHeaders, "Message-Id", fmt.Sprintf("<blackmail-%s-%s@%s>",
			t.UTC().Format("20060102150405.0000"),
			strconv.FormatUint(testRandom(), 36),
			from.Address[strings.Index(from.Address, "@")+1:]))
		writeH(msg, &userHeaders, "Date", t.Format(time.RFC1123Z))
		writeH(msg, &userHeaders, "Subject", subject)

		for i := range userHeaders {
			if i%2 == 1 {
				continue
			}
			writeH(msg, nil, userHeaders[i], userHeaders[i+1])
		}
	}

	// If we have just one text part we don't need to bother with MIME, so just
	// write out the body and return.
	if len(parts) == 1 && parts[0].isText() {
		p := parts[0]
		ct, cte := p.getCTE()
		fmt.Fprintf(msg, "Content-Type: %s\r\n", ct)
		fmt.Fprintf(msg, "Content-Transfer-Encoding: %s\r\n", cte)
		msg.WriteString("\r\n")

		bw := p.writer(msg)
		bw.Write(p.body)
		bw.Close()

		return msg.Bytes(), toList
	}

	// Figure out the correct/best multipart/ format.
	var ct string
	{
		if len(parts) == 1 && parts[0].isMultipart() {
			ct = parts[0].ct
		} else if len(parts) > 2 {
			ct = "multipart/mixed"
		} else {
			ct = "multipart/alternative"
			for _, p := range parts {
				if !p.isTextPlain() && !p.isTextHTML() && p.ct != "multipart/related" {
					ct = "multipart/mixed"
					break
				}
			}
		}
	}

	// Write the message.
	w := multipart.NewWriter(msg)
	if testBoundary != "" {
		if err := w.SetBoundary(testBoundary); err != nil {
			panic(err)
		}
	}

	fmt.Fprint(msg, "Mime-Version: 1.0\r\n")
	fmt.Fprintf(msg, "Content-Type: %s;\r\n\tboundary=\"%s\"\r\n\r\n", ct, w.Boundary())
	si := bodyMIME(msg, w, parts, from.Address)
	w.Close()

	out := msg.Bytes()

	if len(si) > 0 {
		for _, s := range si {
			// TODO: get the actual data.
			toSign := []byte("Content-Transfer-Encoding: quoted-printable\r\n[..]")

			sig, err := signMessage(toSign, s.part.pubkey, s.part.privkey)
			if err != nil {
				panic(err)
			}

			out = bytes.ReplaceAll(out, []byte(s.repl), sig)
		}
	}

	return out, toList
}

type signInfo struct {
	part bodyPart
	repl string
}

func bodyMIME(msg io.Writer, w *multipart.Writer, parts []bodyPart, from string) []signInfo {
	// Gather all cid: links.
	var cids []string
	for _, p := range parts {
		if p.cid != "" {
			cids = append(cids, p.cid)
		}
	}

	var si []signInfo

	for _, p := range parts {
		// Multipart
		if p.isMultipart() {
			// Skip this, as we already set it on the top-level message.
			r := randomBoundary()
			if p.ct == "multipart/signed" {
				p.parts = append(p.parts, bodyPart{
					ct:       "application/pgp-signature",
					attach:   true, // TODO: maybe inline it?
					filename: "signature.asc",
					body:     []byte(r),
				})

				si = append(si, signInfo{part: p, repl: r})
				si = append(si, bodyMIME(msg, w, p.parts, from)...)
				continue
			}

			b := randomBoundary()
			if testBoundary != "" {
				b = testBoundary + "222"
			}
			part, _ := w.CreatePart(textproto.MIMEHeader{
				"Content-Type": {fmt.Sprintf("%s;\r\n\tboundary=\"%s\"", p.ct, b)},
			})

			w2 := multipart.NewWriter(part)
			if err := w2.SetBoundary(b); err != nil {
				panic(err)
			}

			si = append(si, bodyMIME(part, w2, p.parts, from)...)
			w2.Close()
			continue
		}

		ct, cte := p.getCTE()
		head := textproto.MIMEHeader{"Content-Transfer-Encoding": {cte}, "Content-Type": {ct}}
		if p.cid != "" {
			head.Set("Content-ID", "<"+p.cid+">")
		}

		// Attachments.
		if p.attach || p.inlineAttach {
			a := "attachment"
			if p.inlineAttach {
				a = "inline"
			}

			if isMB(p.filename) {
				head.Set("Content-Disposition", fmt.Sprintf("%s; filename*=utf-8''%s",
					a, url.PathEscape(p.filename)))
				head.Set("Content-Type", fmt.Sprintf("%s; name=\"%s\"", ct,
					mime.QEncoding.Encode("utf-8", p.filename)))

			} else {
				f := strings.ReplaceAll(p.filename, `"`, `\"`)
				head.Set("Content-Disposition", fmt.Sprintf("%s; filename=\"%s\"", a, f))
				head.Set("Content-Type", fmt.Sprintf("%s; name=\"%s\"", ct,
					mime.QEncoding.Encode("utf-8", f)))
			}
		}

		// Replace cid: references images.
		if p.isTextHTML() && len(cids) > 0 {
			for j, cid := range cids {
				find := fmt.Sprintf(`src="cid:blackmail:%d"`, j+1)
				p.body = bytes.ReplaceAll(p.body, []byte(find), []byte(`src="cid:`+cid+`"`))
			}
		}

		mp, _ := w.CreatePart(head)
		bw := p.writer(mp)
		bw.Write(p.body)
		bw.Close()
	}

	return si
}

func randomBoundary() string {
	var buf [30]byte
	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", buf[:])
}

func isMB(s string) bool {
	for _, c := range s {
		if c > 0xff {
			return true
		}
	}
	return false
}

func (p bodyPart) isText() bool      { return strings.HasPrefix(p.ct, "text/") }
func (p bodyPart) isTextHTML() bool  { return strings.HasPrefix(p.ct, "text/html") }
func (p bodyPart) isTextPlain() bool { return strings.HasPrefix(p.ct, "text/plain") }
func (p bodyPart) isMultipart() bool { return strings.HasPrefix(p.ct, "multipart/") }

func (p bodyPart) getCTE() (string, string) {
	if p.isText() {
		return fmt.Sprintf("%s; charset=utf-8", p.ct), "quoted-printable"
	}
	if p.ct == "application/pgp-signature" {
		return p.ct, "7bit"
	}
	return p.ct, "base64"
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error             { return nil }
func NopCloser(r io.Writer) io.WriteCloser { return nopCloser{r} }

func (p bodyPart) writer(msg io.Writer) io.WriteCloser {
	if p.isText() {
		return quotedprintable.NewWriter(msg)
	}
	if p.ct == "application/pgp-signature" {
		return NopCloser(msg)
	}
	return &wrappedBase64{msg}
}

func rcpt(kind string, addr ...string) []recipient {
	r := make([]recipient, len(addr))
	for i := range addr {
		r[i] = recipient{kind: kind, Address: mail.Address{Address: addr[i]}}
	}
	return r
}

func rcptAddress(kind string, addr ...mail.Address) []recipient {
	r := make([]recipient, len(addr))
	for i := range addr {
		r[i] = recipient{kind: kind, Address: addr[i]}
	}
	return r
}

func rcptNames(kind string, nameAddr ...string) []recipient {
	if len(nameAddr)%2 == 1 {
		panic(fmt.Sprintf("blackmail.rcptNames for %q: odd argument count", kind))
	}

	r := make([]recipient, len(nameAddr)/2)
	for i := range nameAddr {
		if i%2 == 1 {
			continue
		}
		r[i/2] = recipient{kind: kind, Address: mail.Address{Name: nameAddr[i], Address: nameAddr[i+1]}}
	}
	return r
}

// Write wrapped base64 to w.
type wrappedBase64 struct{ w io.Writer }

func (b *wrappedBase64) Close() error { return nil }

func (b *wrappedBase64) Write(p []byte) (n int, err error) {
	buf := make([]byte, 78)
	copy(buf[76:], "\r\n")

	for len(p) >= 57 {
		base64.StdEncoding.Encode(buf, p[:57])
		b.w.Write(buf)
		p = p[57:]
	}

	if len(p) > 0 {
		base64.StdEncoding.Encode(buf, p)
		b.w.Write(append(buf[:base64.StdEncoding.EncodedLen(len(p))], "\r\n"...))
	}

	return base64.StdEncoding.EncodedLen(len(p)), nil
}

func haveH(headers *[]string, name string) string {
	if headers == nil {
		return ""
	}
	h := *headers
	for i := range h {
		if i%2 == 0 && h[i] == name {
			v := h[i+1]
			*headers = append(h[:i], h[i+2:]...)
			return v
		}
	}
	return ""
}

func writeH(w io.Writer, userHeaders *[]string, key string, values ...string) {
	user := haveH(userHeaders, key)
	if user != "" {
		fmt.Fprintf(w, "%s: %s\r\n", key, mime.QEncoding.Encode("utf-8", user))
		return
	}

	for _, v := range values {
		fmt.Fprintf(w, "%s: %s\r\n", key, mime.QEncoding.Encode("utf-8", v))
	}
}

func writeA(w io.Writer, userHeaders *[]string, key string, addr ...mail.Address) {
	fmt.Fprintf(w, "%s: ", textproto.CanonicalMIMEHeaderKey(key))
	user := haveH(userHeaders, key)
	if user != "" {
		fmt.Fprintf(w, "%s\r\n", user)
		return
	}

	for i, a := range addr {
		fmt.Fprint(w, a.String())
		if i != len(addr)-1 {
			w.Write([]byte(", "))
		}
	}
	w.Write([]byte("\r\n"))
}

func attach(ct, fn string, body []byte) (string, string, string) {
	h := fnv.New32a()
	h.Write(body)
	n := h.Sum32()
	cid := fmt.Sprintf("%s-%s-%s@blackmail",
		now().UTC().Format("20060102150405.0000"),
		strconv.FormatUint(uint64(n), 36),
		strconv.FormatUint(testRandom(), 36))

	switch {
	case fn == "" && ct == "":
		return "data", "application/octet-stream", cid
	case ct == "" && fn != "":
		ct = mime.TypeByExtension(fn)
		if ct == "" {
			ct = http.DetectContentType(body)
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
	case fn == "" && ct != "":
		exts, _ := mime.ExtensionsByType(ct)
		if len(exts) > 0 {
			fn = "attachment" + exts[0]
		}
	}

	return ct, fn, cid
}
