package blackmail

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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

func splitParts(parts []Part) ([]BodyPart, []RcptPart, HeaderPart) {
	var (
		b []BodyPart
		r []RcptPart
		h HeaderPart
	)
	for _, p := range parts {
		switch pp := p.(type) {
		case BodyPart:
			b = append(b, pp)
		case BodyParts:
			b = append(b, pp...)
		case RcptPart:
			r = append(r, pp)
		case RcptParts:
			r = append(r, pp...)
		case HeaderPart:
			h.Append(pp)
		default: // Should never happen.
			panic(fmt.Sprintf("splitParts: %T", pp))
		}
	}
	return b, r, h
}

func message(subject string, from mail.Address, parts ...Part) ([]byte, []string, error) {
	// Propegate any errors from the parts.
	for i, p := range parts {
		if p.Error() != nil {
			return nil, nil, fmt.Errorf("blackmail.Message part %d: %w", i+1, p.Error())
		}
	}

	body, rcpt, headers := splitParts(parts)
	if len(rcpt) == 0 {
		return nil, nil, errors.New("blackmail.Message: need at least one recipient")
	}
	if len(body) == 0 {
		return nil, nil, errors.New("blackmail.Message: need at least one body part")
	}

	msg := new(bytes.Buffer)

	// Write address headers.
	var toList []string
	{
		writeRcpt(msg, "From", from)

		var to, cc, bcc []mail.Address
		for _, r := range rcpt {
			toList = append(toList, r.Address.Address)
			switch r.kind {
			case rcptTo:
				to = append(to, r.Address)
			case rcptCc:
				cc = append(cc, r.Address)
			case rcptBcc:
				bcc = append(bcc, r.Address)
			}
		}

		writeRcpt(msg, "To", to...)
		writeRcpt(msg, "Cc", cc...)
		if len(to) == 0 && len(bcc) > 0 {
			headers.WriteDefault(msg, "To", "undisclosed-recipients:;")
		}
	}

	// Write other headers.
	{
		t := now()
		headers.WriteDefault(msg, "Message-Id", fmt.Sprintf("<blackmail-%s-%s@%s>",
			t.UTC().Format("20060102150405.0000"),
			strconv.FormatUint(testRandom(), 36),
			from.Address[strings.Index(from.Address, "@")+1:]))
		headers.WriteDefault(msg, "Date", t.Format(time.RFC1123Z))
		headers.WriteDefault(msg, "Subject", subject)
		headers.Write(msg)
	}

	// If we have just one text part we don't need to bother with MIME, so just
	// write out the body and return.
	if len(body) == 1 && body[0].isText() {
		p := body[0]
		ct, cte := p.cte()
		fmt.Fprintf(msg, "Content-Type: %s\r\n", ct)
		fmt.Fprintf(msg, "Content-Transfer-Encoding: %s\r\n", cte)
		msg.WriteString("\r\n")

		bw := p.writer(msg)
		bw.Write(p.body)
		bw.Close()

		return msg.Bytes(), toList, nil
	}

	// Figure out the best multipart/ format.
	var ct string
	{
		if len(body) == 1 && body[0].isMultipart() {
			ct = body[0].ct
		} else if len(body) > 2 {
			ct = "multipart/mixed"
		} else {
			ct = "multipart/alternative"
			for _, p := range body {
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
			return nil, nil, fmt.Errorf("blackmail.Message: %w", err)
		}
	}

	fmt.Fprint(msg, "Mime-Version: 1.0\r\n")
	fmt.Fprintf(msg, "Content-Type: %s;\r\n\tboundary=\"%s\"\r\n\r\n", ct, w.Boundary())
	err := bodyMIME(msg, w, body, from.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("blackmail.Message: %w", err)
	}
	w.Close()

	out := msg.Bytes()
	return out, toList, nil
}

func bodyMIME(msg io.Writer, w *multipart.Writer, parts []BodyPart, from string) error {
	// Gather all cid: links.
	var cids []string
	for _, p := range parts {
		if p.cid != "" {
			cids = append(cids, p.cid)
		}
	}

	for _, p := range parts {
		// Multipart
		if p.isMultipart() {
			b := randomBoundary()
			if testBoundary != "" {
				b = testBoundary + "222"
			}
			part, _ := w.CreatePart(textproto.MIMEHeader{
				"Content-Type": {fmt.Sprintf("%s;\r\n\tboundary=\"%s\"", p.ct, b)},
			})

			w2 := multipart.NewWriter(part)
			if err := w2.SetBoundary(b); err != nil {
				return err
			}

			bodyMIME(part, w2, p.parts, from)
			w2.Close()
			continue
		}

		ct, cte := p.cte()
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

			if isASCII(p.filename) {
				f := strings.ReplaceAll(p.filename, `"`, `\"`)
				head.Set("Content-Disposition", fmt.Sprintf("%s; filename=\"%s\"", a, f))
				head.Set("Content-Type", fmt.Sprintf("%s; name=\"%s\"", ct,
					mime.QEncoding.Encode("utf-8", f)))
			} else {
				head.Set("Content-Disposition", fmt.Sprintf("%s; filename*=utf-8''%s",
					a, url.PathEscape(p.filename)))
				head.Set("Content-Type", fmt.Sprintf("%s; name=\"%s\"", ct,
					mime.QEncoding.Encode("utf-8", p.filename)))
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
	return nil
}

func randomBoundary() string {
	var buf [30]byte
	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic(err) // Should never fail.
	}
	return fmt.Sprintf("%x", buf[:])
}

func isASCII(s string) bool {
	for _, c := range s {
		if c > 0x7f {
			return false
		}
	}
	return true
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
