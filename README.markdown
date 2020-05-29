Blackmail is a Go package to send emails with a friendly API.

Why a new package? I didn't care much for the API of many of the existing
solutions.

There is also an SMTP client library at `zgo.at/blackmail/smtp` which can be
used without the main blackmail client as a replacement for the frozen
`net/smtp` (mostly but not 100% compatible). This is a modified version of
net/smtp (via [go-smtp][go-smtp], although I removed most added features from
that and kept just the client-related fixes and enhancements).

There is a small commandline utility at `cmd/blackmail`.

This package is not intended as a one-stop-shop for all your email needs;
non-goals include things like parsing email messages, support for encodings
other than ASCII and UTF-8, or very specific complex requirements. It should be
able to handle all common (and not-so-common) use cases though.

Import the library as `zgo.at/blackmail` – API docs: https://pkg.go.dev/zgo.at/blackmail

[go-smtp]: https://github.com/emersion/go-smtp

Usage
-----
There are two parts: `blackmail.Message()` which creates a message to be
formatted, and `blackmail.Mailer()` which accepts a message and sends it out.
There are several supported mailers.

The Message() function works like this:

    func Message(subject string, from mail.Address, parts ...Part) ([]byte, []string, error)

The `subject` and `from` and the email's subject and sender, and `parts` are a
list "email parts": headers, recipients, and bodies.

For example:

    blackmail.Message("Send me bitcoins or I will leak your browsing history!",
        blackmail.From("", "blackmail@example.com"),
        blackmail.To("Name", "victim@example.com"),
        blackmail.BodyText("I can haz ur bitcoinz?"))

You need at least one recipient (to, cc, bcc) part and one body part.

(Aside: I spent a long time trying to come up with a way that enforces this
through typing, but all end up with ugly/complex `append()` chains).

There are currently:

    NewMailerWriter()       Write to an io.Writer, such as os.Stderr
    NewMailerSMTP()         Use SMTP, possibly via a relay.
    NewMailerSendGrid()     Use the SendGrid API.


The `blackmail.Send()` function creates a message with `Message()` and then uses
`blackmail.DefaultMailer` to send it off.

### Examples

```go
// Send a new message using blackmail.DefaultMailer
err := blackmail.Send("Send me bitcoins or I will leak your browsing history!",
    blackmail.From("", "blackmail@example.com"),
    blackmail.To("Name", "victim@example.com"),
    blackmail.Bodyf("I can haz ur bitcoinz?"))

// A more complex message with a text and HTML part and inline image.
err = blackmail.Send("I saw what you did last night 😏",
    blackmail.From("😏", "blackmail@example.com"),
    append(blackmail.To("Name", "victim@example.com"), blackmail.Cc("Other", "other@example.com")...),
    blackmail.BodyText("Text part"),
    blackmail.BodyHTML(`HTML part: <img src="cid:blackmail:1">`,
        blackmail.InlineImage("image/png", "logo.png", []byte{0x00, 0x01, 0x02})))

// You can create your own (re-usable) mailer.
mailer := blackmail.NewMailer("smtp://user:pass@localhost:25")
err = mailer.Send()

// Add some options to your mailer.
mailer = blackmail.NewMailer("smtp://user:pass@localhost:25",
    blackmail.MailerAuth(),
    blackmail.MailerTLS(&tls.Config{}),
    blackmail.RequireSTARTLS(true))

// Get RF5322 message with a list of recipients to send it to (To + Cc + Bcc).
msg, to, err := blackmail.Message(/* same arguments as Send() */)
```

See the test cases in [`blackmail_test.go`](/blackmail_test.go#L21) for various
other examples.


Questions you may have 
----------------------

### I get the error "tls: first record does not look like a TLS handshake"

You are attempting to establish a TLS connection to a server which doesn't
support TLS or only supports it via the `STARTTLS` command.

### I get the error "x509: certificate signed by unknown authority"

The certificate chain used for the TLS connection is not signed by a known
authority. It's a self-signed certificate or you don't have the root
certificates installed.

### How can I use a @ in my username?

Encode it as `%40`:

    smtp://user%example.com:passwd@smtp.example.com:587'


Dedication
----------

I first had the idea of *blackmail* well over 10 years ago after seeing some Joe
Armstrong interview where he mentioned he or a co-worker (I forgot) maintained
an email client in the 80s *blackmail*. I rewrote my PHP "mailview" webmail
client to Python years ago and called it blackmail, but never finished or
released it.

Finally, after all these years I have a change to ~steal~ use the *blackmail*
name for an email-related thing!

This package is dedicated to Joe Armstrong. I never programmed Erlang, but found
many of his writings and talks insightful, and – more importantly – he was a
funny guy.

*…and now for the tricky bit…*
