package smtp

// Note: most of this code was copied, with some modifications, from net/smtp.

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"fmt"
)

// Common SASL errors.
var (
	ErrUnexpectedAuthResponse    = errors.New("sasl: unexpected client response")
	ErrUnexpectedServerChallenge = errors.New("sasl: unexpected server challenge")
)

// Auth interface to perform challenge-response authentication.
type Auth interface {
	// Begins SASL authentication with the server. It returns the
	// authentication mechanism name and "initial response" data (if required by
	// the selected mechanism). A non-nil error causes the client to abort the
	// authentication attempt.
	//
	// A nil ir value is different from a zero-length value. The nil value
	// indicates that the selected mechanism does not use an initial response,
	// while a zero-length value indicates an empty initial response, which must
	// be sent to the server.
	Start() (mech string, ir []byte, err error)

	// Continues challenge-response authentication. A non-nil error causes
	// the client to abort the authentication attempt.
	Next(challenge []byte) (response []byte, err error)
}

type plainAuth struct{ Identity, Username, Password string }

func (a *plainAuth) Start() (mech string, ir []byte, err error) {
	return "PLAIN", []byte(a.Identity + "\x00" + a.Username + "\x00" + a.Password), nil
}

func (a *plainAuth) Next(challenge []byte) (response []byte, err error) {
	return nil, ErrUnexpectedServerChallenge
}

// PlainAuth implements the PLAIN authentication mechanism as described in RFC
// 4616. Authorization identity may be left blank to indicate that it is the
// same as the username.
func PlainAuth(identity, username, password string) Auth {
	return &plainAuth{identity, username, password}
}

type loginAuth struct{ Username, Password string }

func (a *loginAuth) Start() (mech string, ir []byte, err error) {
	return "LOGIN", []byte(a.Username), nil
}

func (a *loginAuth) Next(challenge []byte) (response []byte, err error) {
	if !bytes.Equal(challenge, []byte("Password:")) {
		return nil, ErrUnexpectedServerChallenge
	}
	return []byte(a.Password), nil
}

// LoginAuth implements of the LOGIN authentication mechanism as described in
// http://www.iana.org/go/draft-murchison-sasl-login
func LoginAuth(username, password string) Auth {
	return &loginAuth{username, password}
}

type cramMD5Auth struct{ Username, Secret string }

func (a *cramMD5Auth) Start() (mech string, ir []byte, err error) {
	return "CRAM-MD5", nil, nil
}

func (a *cramMD5Auth) Next(challenge []byte) (response []byte, err error) {
	d := hmac.New(md5.New, []byte(a.Secret))
	d.Write(challenge)
	s := make([]byte, 0, d.Size())
	return []byte(fmt.Sprintf("%s %x", a.Username, d.Sum(s))), nil
}

// CramMD5Auth implements the CRAM-MD5 authentication mechanism, as described in
// RFC 2195.
//
// The returned Auth uses the given username and secret to authenticate to the
// server using the challenge-response mechanism.
func CramMD5Auth(username, secret string) Auth {
	return &cramMD5Auth{username, secret}
}
