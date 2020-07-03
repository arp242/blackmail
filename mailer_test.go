package blackmail

import (
	"bytes"
	"sync"
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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		err := m.Send("Subject!",
			From("My name", "myemail@example.com"),
			To("Name", "addr"),
			Bodyf("Well, hello there!"))
		if err != nil {
			t.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()

		err := m.Send("Subject!",
			From("My name", "myemail@example.com"),
			To("Name", "addr"),
			Bodyf("Well, hello there!"))
		if err != nil {
			t.Fatal(err)
		}
	}()

	wg.Wait()

	out := buf.String()
	if len(out) < 100 {
		t.Errorf("short output length")
	}
}
