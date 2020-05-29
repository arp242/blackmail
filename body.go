package blackmail

import (
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"strings"
)

// BodyPart defines the body. Create a new one with one of the Body* or
// Attachment* functions.
type BodyPart struct {
	err          error
	parts        []BodyPart
	ct           string
	body         []byte
	filename     string
	attach       bool
	inlineAttach bool
	cid          string // Content-ID reference
}

func (BodyPart) blackmail()     {}
func (p BodyPart) Error() error { return p.err }

type BodyParts []BodyPart

func (BodyParts) blackmail()     {}
func (p BodyParts) Error() error { return nil }

func (p BodyPart) isText() bool      { return strings.HasPrefix(p.ct, "text/") }
func (p BodyPart) isTextHTML() bool  { return strings.HasPrefix(p.ct, "text/html") }
func (p BodyPart) isTextPlain() bool { return strings.HasPrefix(p.ct, "text/plain") }
func (p BodyPart) isMultipart() bool { return strings.HasPrefix(p.ct, "multipart/") }

// Get the Content-Type and Content-Transfer-Encoding
func (p BodyPart) cte() (string, string) {
	if p.isText() {
		return p.ct + "; charset=utf-8", "quoted-printable"
	}
	if p.ct == "application/pgp-signature" {
		return p.ct, "7bit"
	}
	return p.ct, "base64"
}

func (p BodyPart) writer(msg io.Writer) io.WriteCloser {
	if p.isText() {
		return quotedprintable.NewWriter(msg)
	}
	return &wrappedBase64{msg}
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
