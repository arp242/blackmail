package smtp_test

import (
	"bytes"
	"testing"

	"zgo.at/blackmail/smtp"
)

func TestPlainAuth(t *testing.T) {
	c := smtp.PlainAuth("identity", "username", "password")

	mech, ir, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "PLAIN" {
		t.Error("Invalid mechanism name:", mech)
	}

	want := []byte{105, 100, 101, 110, 116, 105, 116, 121, 0, 117, 115, 101, 114, 110, 97, 109, 101, 0, 112, 97, 115, 115, 119, 111, 114, 100}
	if !bytes.Equal(ir, want) {
		t.Error("Invalid initial response:", ir)
	}
}

func TestLoginAuth(t *testing.T) {
	c := smtp.LoginAuth("username", "Password:")

	mech, resp, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "LOGIN" {
		t.Error("Invalid mechanism name:", mech)
	}

	want := []byte{117, 115, 101, 114, 110, 97, 109, 101}
	if !bytes.Equal(resp, want) {
		t.Error("Invalid initial response:", resp)
	}

	_, err = c.Next(want)
	if err != smtp.ErrUnexpectedServerChallenge {
		t.Error("Invalid chalange")
	}

	want = []byte("Password:")
	resp, err = c.Next(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp, want) {
		t.Error("Invalid initial response:", resp)
	}
}
