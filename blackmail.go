// Package blackmail sends emails.
package blackmail

// This file contains the public API to create messages.

import (
	"fmt"
	"net/mail"
)

// Body returns a new part with the given Content-Type.
func Body(contentType string, body []byte) bodyPart {
	return bodyPart{ct: contentType, body: body}
}

// Bodyf returns a new text/plain part.
func Bodyf(s string, args ...interface{}) bodyPart {
	return BodyText([]byte(fmt.Sprintf(s, args...)))
}

// BodyText returns a new text/plain part.
func BodyText(body []byte) bodyPart { return Body("text/plain", body) }

// BodyHTML returns a new text/html part.
func BodyHTML(body []byte, images ...bodyPart) bodyPart {
	if len(images) == 0 {
		return Body("text/html", body)
	}

	return bodyPart{
		ct:    "multipart/related",
		parts: append([]bodyPart{Body("text/html", body)}, images...),
	}
}

// Attachment returns a new attachment part with the given Content-Type.
//
// It will try to guess the Content-Type if empty.
func Attachment(contentType, filename string, body []byte) bodyPart {
	contentType, filename, cid := attach(contentType, filename, body)
	return bodyPart{ct: contentType, filename: filename, attach: true, body: body, cid: cid}
}

// InlineImage returns a new inline image part.
//
// It will try to guess the Content-Type if empty.
//
// Then use "cid:blackmail:<n>" to reference it:
//
//    <img src="cid:blackmail:1">     First InlineImage()
//    <img src="cid:blackmail:2">     Second InlineImage()
func InlineImage(contentType, filename string, body []byte) bodyPart {
	contentType, filename, cid := attach(contentType, filename, body)
	return bodyPart{ct: contentType, filename: filename, inlineAttach: true, body: body, cid: cid}
}

// Headers adds the headers to the message.
//
// This will override any headers set automatically by the system, such as Date:
// or Message-Id:
//
//   Headers("My-Header", "value",
//       "Message-Id", "<my-message-id@example.com>")
func Headers(keyValue ...string) bodyPart {
	if len(keyValue)%2 == 1 {
		panic("blackmail.Headers: odd argument count")
	}
	return bodyPart{ct: "HEADERS", headers: keyValue}
}

// HeadersAutoreply sets headers to indicate this message is a an autoreply.
//
// See e.g: https://www.arp242.net/autoreply.html#what-you-need-to-set-on-your-auto-response
func HeadersAutoreply() bodyPart {
	return Headers("Auto-Submitted", "auto-replied",
		"X-Auto-Response-Suppress", "All",
		"Precedence", "auto_reply")
}

// Sign the message with the given PGP key.
func Sign(pubkey, privkey []byte, parts ...bodyPart) bodyPart {
	return bodyPart{ct: "multipart/signed", parts: parts, pubkey: pubkey, privkey: privkey}
}

// Address makes creating a mail.Address a bit more convenient.
//
//   mail.Address{Name: "foo, Address: "foo@example.com}
//   blackmail.Address{"foo, "foo@example.com)
func Address(name, address string) mail.Address {
	return mail.Address{Name: name, Address: address}
}

// To sets the To: from a list of email addresses.
func To(addr ...string) []recipient  { return rcpt("to", addr...) }
func Cc(addr ...string) []recipient  { return rcpt("cc", addr...) }
func Bcc(addr ...string) []recipient { return rcpt("bcc", addr...) }

// ToAddress sets the To: from a list of mail.Addresses.
func ToAddress(addr ...mail.Address) []recipient  { return rcptAddress("to", addr...) }
func CcAddress(addr ...mail.Address) []recipient  { return rcptAddress("cc", addr...) }
func BccAddress(addr ...mail.Address) []recipient { return rcptAddress("bcc", addr...) }

// ToNames sets the To: from a list of "name", "addr" arguments.
func ToNames(nameAddr ...string) []recipient  { return rcptNames("to", nameAddr...) }
func CcNames(nameAddr ...string) []recipient  { return rcptNames("cc", nameAddr...) }
func BccNames(nameAddr ...string) []recipient { return rcptNames("bcc", nameAddr...) }

// TODO: maybe also add helpers to parse?
// func ToParse(in string) []recipient { return rcpt(mail.Parse(in)) }

// Message formats a message.
func Message(subject string, from mail.Address, rcpt []recipient, parts ...bodyPart) ([]byte, []string) {
	return message(subject, from, rcpt, parts...)
}
