package blackmail

import (
	"bytes"
	"sync"
	"testing"
)

func TestMailerWriter(t *testing.T) {
	buf := new(bytes.Buffer)
	m := NewMailerWriter(buf)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		err := m.Send("Subject!",
			From("My name", "myemail@example.com"),
			To("Name", "addr"),
			BodyText("Well, hello there!"))
		if err != nil {
			t.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()
		err := m.Send("Subject!",
			From("My name", "myemail@example.com"),
			To("Name", "addr"),
			BodyText("Well, hello there!"))
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
