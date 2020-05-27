package blackmail

import (
	"bytes"
	"testing"
)

var (
	_ sender = senderWriter{}
	_ sender = senderRelay{}
	_ sender = senderDirect{}
)

func TestMailerStdout(t *testing.T) {
	buf := new(bytes.Buffer)
	m := NewMailer(ConnectWriter, MailerOut(buf))

	err := m.Send("Subject!",
		From("My name", "myemail@example.com"),
		To("Name", "addr"),
		Bodyf("Well, hello there!"))
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if len(out) < 100 {
		t.Errorf("short output length")
	}
}
