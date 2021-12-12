package blackmail

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/mail"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"zgo.at/zstd/ztest"
	"zgo.at/zstd/ztest/image"
)

func TestMessage(t *testing.T) {
	tests := []struct {
		file string
		in   func() ([]byte, []string, error)
		to   []string
	}{
		// A basic example; doesn't create a MIME message.
		{"basic", func() ([]byte, []string, error) {
			return Message("Basic test", From("", "me@example.com"),
				To("to@to.to"),
				Bodyf("Hello=there"))
		}, []string{"to@to.to"}},

		// Add CC address.
		{"cc", func() ([]byte, []string, error) {
			return Message("Cc/Bcc", From("", "me@example.com"),
				append(To("to@to.to"), Cc("cc@cc.occ", "asd@asd.qqq")...),
				Bodyf("Hello=there"))
		}, []string{"to@to.to", "cc@cc.occ", "asd@asd.qqq"}},

		// Add names to the addresses.
		{"names", func() ([]byte, []string, error) {
			to := mail.Address{Name: "to", Address: "to@to.to"}

			return Message("Names", From("me", "me@example.com"),
				append(ToAddress(to), CcNames("cc", "cc@cc.occ", "cc2", "asd@asd.qqq")...),
				Bodyf("Hello=there"))
		}, []string{"to@to.to", "cc@cc.occ", "asd@asd.qqq"}},

		// Add Bcc: addresses; they don't show up in the message, but do in the
		// return list of addresses for sending.
		{"cc", func() ([]byte, []string, error) {
			return Message("Cc/Bcc", From("", "me@example.com"),
				append(To("to@to.to"), append(Cc("cc@cc.occ", "asd@asd.qqq"), Bcc("bcc@bcc.bcc", "x@x.x")...)...),
				Bodyf("Hello=there"))
		}, []string{"to@to.to", "cc@cc.occ", "asd@asd.qqq", "bcc@bcc.bcc", "x@x.x"}},

		// Only Bcc: will set "To: undisclosed-recipients:;"
		{"bcc", func() ([]byte, []string, error) {
			return Message("Only Bcc", From("", "me@example.com"),
				Bcc("bcc@bcc.bcc", "x@x.x"),
				Bodyf("Newsletter"))
		}, []string{"bcc@bcc.bcc", "x@x.x"}},

		// Set your own headers.
		{"headers", func() ([]byte, []string, error) {
			return Message("Custom headers", From("", "me@example.com"),
				To("to@to.to"),
				Bodyf("Hello=there"), Headers("Header", "value", "X-Mine", "qwe", "X-MINE", "2nd"))
		}, []string{"to@to.to"}},

		// Passed headers overwrite default ones.
		{"headers-overwrite", func() ([]byte, []string, error) {
			return Message("Customer headers overwrite", From("", "me@example.com"),
				To("to@to.to"),
				Bodyf("Hello=there"), Headers("Header", "value", "MESSAGE-ID", "ID"))
		}, []string{"to@to.to"}},

		// multipart/alternative with a text and html variant.
		{"alternative", func() ([]byte, []string, error) {
			return Message("text and html", From("", "me@example.com"),
				To("to@to.to"),
				BodyText([]byte("<b>text</b> <")),
				BodyHTML([]byte("<b>html</b> <")))
		}, []string{"to@to.to"}},

		// Attachments.
		{"attachment", func() ([]byte, []string, error) {
			return Message("Attachment", From("", "me@example.com"),
				To("to@to.to"),
				BodyText([]byte("Look at my images!")),
				Attachment("image/png", "test.png", image.PNG),
				Attachment("image/jpeg", "test \".jpeg", image.JPEG))
		}, []string{"to@to.to"}},

		// Attachments with unicode filenames.
		{"utf8-filenames", func() ([]byte, []string, error) {
			return Message("Unicode attachment", From("", "me@example.com"),
				To("to@to.to"),
				BodyText([]byte("Look at my images!")),
				Attachment("image/png", "€.png", image.PNG),
				Attachment("image/jpeg", "€ \".jpeg", image.JPEG))
		}, []string{"to@to.to"}},

		// Inline images.
		{"inline-image", func() ([]byte, []string, error) {
			return Message("Inline image", From("", "me@example.com"),
				To("to@to.to"),
				Bodyf("Use HTML for images"),
				BodyHTML(
					[]byte(`Look at my image bro: <img src="cid:blackmail:1"></a>`),
					InlineImage("image/png", "inline.png", image.PNG)))
		}, []string{"to@to.to"}},

		// Load from template.
		{"template", func() ([]byte, []string, error) {
			tpl := template.Must(template.New("email").Parse("Hello {{.Name}}"))
			helper := func(tplname string, args interface{}) func() ([]byte, error) {
				return func() ([]byte, error) {
					buf := new(bytes.Buffer)
					err := tpl.ExecuteTemplate(buf, tplname, args)
					return buf.Bytes(), err
				}
			}

			return Message("From template", From("", "me@example.com"),
				To("to@to.to"),
				BodyMustText(helper("email", struct{ Name string }{"Martin"})))
		}, []string{"to@to.to"}},

		// A somewhat complicated "autoresponder" message which:
		//
		// - Sets header to indicate this is an autoreply.
		// - Adds a HTML part with an inline image.
		// - Sets In-Reply-To and List-Id
		// - Adds a quoted previous part ← TODO: need to add API for this.
		{"headers-autoreply", func() ([]byte, []string, error) {
			return Message("Re: autoreply", From("", "me@example.com"),
				append(ToNames("Customer", "cust@example.com"), CcAddress(mail.Address{Address: "x@x.x"})...),
				HeadersAutoreply(),
				Headers("List-Id", "<foo>",
					"In-Reply-To", "<prev-msgid@example.com>"),
				BodyText([]byte("Auto respond")),
				BodyHTML(
					[]byte(`<b>Auto respond</b><br><img src="cid:blackmail:1"`),
					InlineImage("", "logo.png", image.PNG)))
		}, []string{"cust@example.com", "x@x.x"}},
	}

	now = func() time.Time { return time.Date(2019, 6, 18, 13, 37, 00, 123456789, time.UTC) }
	testRandom = func() uint64 { return 42 }
	testBoundary = "XXX"

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			f, err := os.ReadFile("testdata/" + tt.file + ".eml")
			if err != nil {
				m, _, _ := tt.in()
				t.Log("\n" + string(m)) // So we can copy/paste when writing new tests.
				t.Fatalf("read testdata/%s: %s.eml", tt.file, err)
			}

			want := string(f)
			msg, to, err := tt.in()
			if err != nil {
				t.Fatalf("Message() error: %s", err)
			}
			out := string(msg)
			if d := ztest.Diff(out, want); d != "" {
				t.Error(strings.ReplaceAll(d, "\r", "\\r"))
			}
			if !reflect.DeepEqual(tt.to, to) {
				t.Errorf("to wrong\ngot:  %v\nwant: %s", to, tt.to)
			}
		})
	}
}

func TestMessageError(t *testing.T) {
	tests := []struct {
		wantErr string
		in      func() ([]byte, []string, error)
	}{
		{"blackmail.Message part 1: oh noes!", func() ([]byte, []string, error) {
			return Message("From template", From("", "me@example.com"),
				To("to@to.to"),
				BodyMustText(func() ([]byte, error) {
					return nil, errors.New("oh noes!")
				}))
		}},

		{"blackmail.Headers: odd argument count", func() ([]byte, []string, error) {
			return Message("From template", From("", "me@example.com"),
				To("to@to.to"),
				Headers(""))
		}},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, _, err := tt.in()
			if !ztest.ErrorContains(err, tt.wantErr) {
				t.Errorf("wrong error:\ngot:  %s\nwant: %s", err, tt.wantErr)
			}
		})
	}
}

func BenchmarkSimple(b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		_, _, _ = Message("Hello!", From("", "me@example.com"),
			To("to@to.to"),
			BodyText([]byte("<b>text</b> <")))
	}
}

func BenchmarkMIME(b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		_, _, _ = Message("Hello!", From("", "me@example.com"),
			To("to@to.to"),
			BodyText([]byte("<b>text</b> <")),
			BodyHTML([]byte("<b>html</b> <")))
	}
}

func BenchmarkBase64(b *testing.B) {
	b.ReportAllocs()
	w := wrappedBase64{new(bytes.Buffer)}
	for n := 0; n < b.N; n++ {
		w.Write(image.JPEG)
	}
}
