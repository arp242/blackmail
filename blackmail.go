// Package blackmail sends emails.
package blackmail

import (
	"fmt"
	"net/mail"
)

// Part is a part of a message, which can be a body part, attachment, recipient,
// or header.
type Part interface {
	Error() error

	// Unexported method, so this is a "private" interface which can't be
	// implemented by other packages.
	blackmail()
}

// Parts is a list of parts.
type Parts []Part

// func (Parts) blackmail() {}

// Body returns a new body part with the given Content-Type.
func Body(contentType string, body string) BodyPart {
	return BodyPart{ct: contentType, body: []byte(body)}
}

// Bodyf returns a new body part with the given Content-Type.
func Bodyf(contentType, s string, args ...interface{}) BodyPart {
	return BodyText(fmt.Sprintf(s, args...))
}

// BodyText returns a new text/plain part.
func BodyText(body string) BodyPart { return Body("text/plain", body) }

// BodyTextf returns a new text/plain part.
func BodyTextf(body string, args ...interface{}) BodyPart {
	return BodyText(fmt.Sprintf(body, args...))
}

// BodyHTML returns a new text/html part.
//
// images can be a list of body parts to be used as multipart/related images.
func BodyHTML(body string, images ...BodyPart) BodyPart {
	if len(images) == 0 {
		return Body("text/html", body)
	}
	return BodyPart{
		ct:    "multipart/related",
		parts: append([]BodyPart{Body("text/html", body)}, images...),
	}
}

// BodyFunc sets the body using a callback, propagating any errors back up.
//
// This is useful when using Go templates for the mail body;
//
//    buf := new(bytes.Buffer)
//    err := tpl.ExecuteTemplate(buf, "email", struct{
//        Name string
//    }{"Martin"})
//    if err != nil {
//        log.Fatal(err)
//    }
//
//    err := Send("Basic test", From("", "me@example.com"),
//        To("to@to.to"),
//        Body("text/plain", buf.Bytes()))
//
// With BodyFunc(), it's simpler; you just need to define a little helper
// re-usable helper function and call that:
//
//    func template(tplname string, args interface{}) func() ([]byte, error) {
//        return func() ([]byte, error) {
//            buf := new(bytes.Buffer)
//            err := tpl.ExecuteTemplate(buf, tplname, args)
//            return buf.Bytes(), err
//        }
//    }
//
//    err := Send("Basic test", From("", "me@example.com"),
//        To("to@to.to"),
//        BodyFunc("text/html", template("email", struct {
//            Name string
//        }{"Martin"})))
//
// Other use cases include things like loading data from a file, reading from a
// stream, etc.
func BodyFunc(contentType string, fn func() (string, error)) BodyPart {
	body, err := fn()
	return BodyPart{ct: contentType, err: err, body: []byte(body)}
}

// BodyFuncText is like BodyFunc() with contentType text/plain.
func BodyFuncText(fn func() (string, error)) BodyPart {
	return BodyFunc("text/plain", fn)
}

// BodyFuncHTML is like BodyFunc() with contentType text/html.
func BodyFuncHTML(fn func() (string, error)) BodyPart {
	return BodyFunc("text/html", fn)
}

// Attachment returns a new attachment part with the given Content-Type.
//
// It will try to guess the Content-Type if empty.
func Attachment(contentType, filename string, body []byte) BodyPart {
	contentType, filename, cid := attach(contentType, filename, body)
	return BodyPart{ct: contentType, filename: filename, attach: true, body: body, cid: cid}
}

// InlineImage returns a new inline image part.
//
// It will try to guess the Content-Type if empty.
//
// Use "cid:blackmail:<n>" to reference it in a HTML body:
//
//    <img src="cid:blackmail:1">     First InlineImage()
//    <img src="cid:blackmail:2">     Second InlineImage()
func InlineImage(contentType, filename string, body []byte) BodyPart {
	contentType, filename, cid := attach(contentType, filename, body)
	return BodyPart{ct: contentType, filename: filename, inlineAttach: true, body: body, cid: cid}
}

// Headers adds the headers to the message.
//
// This will override any headers set automatically by the system, such as Date:
// or Message-Id:
//
//   Headers("My-Header", "value",
//       "Message-Id", "<my-message-id@example.com>")
func Headers(keyValue ...string) HeaderPart {
	return HeaderPart{}.FromList(keyValue)
}

// HeadersAutoreply sets headers to indicate this message is a an autoreply.
//
// See: https://www.arp242.net/autoreply.html#what-you-need-to-set-on-your-auto-response
func HeadersAutoreply() HeaderPart {
	return Headers("Auto-Submitted", "auto-replied",
		"X-Auto-Response-Suppress", "All",
		"Precedence", "auto_reply")
}

// From creates a mail.Address with a name and email address.
//
//   blackmail.From("foo, "foo@example.com)
//
// Is identical to:
//
//   mail.Address{Name: "foo, Address: "foo@example.com}
func From(name, address string) mail.Address {
	return mail.Address{Name: name, Address: address}
}

// To sets the To: from a name and email address.
func To(name, addr string) RcptPart  { return rcptOne(rcptTo, name, addr) }
func Cc(name, addr string) RcptPart  { return rcptOne(rcptCc, name, addr) }
func Bcc(name, addr string) RcptPart { return rcptOne(rcptBcc, name, addr) }

// ToNames sets the To: from a list of "name", "addr" arguments.
func ToNames(nameAddr ...string) RcptParts  { return rcptNames(rcptTo, nameAddr) }
func CcNames(nameAddr ...string) RcptParts  { return rcptNames(rcptCc, nameAddr) }
func BccNames(nameAddr ...string) RcptParts { return rcptNames(rcptBcc, nameAddr) }

// ToAddr sets the To: from a list of mail.Addresses.
func ToAddr(addr ...mail.Address) RcptParts  { return rcptAddr(rcptTo, addr) }
func CcAddr(addr ...mail.Address) RcptParts  { return rcptAddr(rcptCc, addr) }
func BccAddr(addr ...mail.Address) RcptParts { return rcptAddr(rcptBcc, addr) }

// ToList sets the To: from a list of addresses. This does not set any name.
func ToList(addr ...string) RcptParts  { return rcptList(rcptTo, addr) }
func CcList(addr ...string) RcptParts  { return rcptList(rcptCc, addr) }
func BccList(addr ...string) RcptParts { return rcptList(rcptBcc, addr) }

// Message creates a RFC-5322 formatted message.
func Message(subject string, from mail.Address, parts ...Part) ([]byte, []string, error) {
	return message(subject, from, parts...)
}
