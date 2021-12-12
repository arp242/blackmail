Blackmail is a Go package to send emails.

Current status: **work-in-progress**. Most of it works, but the API isn't stable
yet and some things are not yet implemented as documented.

Why a new package? I didn't care much for the API of many of the existing
solutions.

Import the library as `zgo.at/blackmail`; API docs: https://godocs.io/zgo.at/blackmail

There is also a smtp client library at `zgo.at/blackmail/smtp` which can be used
without the main blackmail client if you want. It's a modified version of
net/smtp (via [go-smtp][go-smtp], although I removed most added features from
that).

There is a small commandline utility at `cmd/blackmail`; try it with `go run
./cmd/blackmail`.

The main use case where you just want to send off an email and be done with it.
Non-goals include things like parsing email messages, support for encodings
other than ASCII and UTF-8, or a one-stop-shop for your very specific complex
requirements. It should be able to handle all common (and not-so-common) use
cases though.

[go-smtp]: https://github.com/emersion/go-smtp

Example
-------

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
    blackmail.Text("Text part")
    blackmail.HTML("HTML part: <img src="cid:blackmail:1">",
        blackmail.InlineImage("image/png", "logo.png", imgbytes)))

// You can create your own (re-usable) mailer.
mailer := blackmail.NewMailer("smtp://user:pass@localhost:25")
err = mailer.Send([..])

// Add some options to your mailer.
mailer = blackmail.NewMailer("smtp://user:pass@localhost:25
    blackmail.MailerAuth(..),
    blackmail.MailerTLS(&tls.Config{}),
    blackmail.RequireSTARTLS(true))

// Get RF5322 message with a list of recipients to send it to (To + Cc + Bcc).
msg, to := blackmail.Message([.. same arguments as Send() ..])
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

Encode as `%40`:

    smtp://carpetsmoker%40fastmail.nl:PASS@smtp.fastmail.com:587'


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


