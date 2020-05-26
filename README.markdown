Blackmail is a Go package to send emails. It has an easy to use API and supports
email signing without too much effort.

Current status: **work-in-progress**. Most of it works, but the API isn't stable
yet and some things are not yet implemented as documented (specifically: signing
and "direct" sending doesn't work yet, and some Mailer options don't either).

Why a new package? I didn't care much for the API of many of the existing
solutions. I also wanted an email package which supports easy PGP signing
out-of-the-box (see [this article][sign] for some background on that).

Import the library as `zgo.at/blackmail`; [godoc][godoc]. There is also a smtp
client library at `zgo.at/blackmail/smtp` which can be used without the main
blackmail client if you want. It's a modified version of net/smtp (via
[go-smtp][go-smtp], although I removed most added features from that).

There is a small commandline utility at `cmd/blackmail`; try it with `go run
./cmd/blackmail`.

The main use case where you just want to send off an email and be done with it.
Non-goals include things like parsing email messages or a one-stop-shop for your
very specific complex requirements. It should be able to handle all common (and
not-so-common) use cases though.

[godoc]: https://pkg.go.dev/zgo.at/blackmail
[sign]: https://www.arp242.net/signing-emails.html
[go-smtp]: https://github.com/emersion/go-smtp

Example
-------

```go
// Send a new message using blackmail.DefaultMailer
err := blackmail.Send("Send me bitcoins or I will leak your browsing history!",
    blackmail.Address("", "blackmail@example.com"),
    blackmail.To("Name", "victim@example.com"),
    blackmail.Bodyf("I can haz ur bitcoinz?"))

// A more complex message.
err = blackmail.Send("I saw what you did last night 😏",
    blackmail.Address("😏", "blackmail@example.com"),
    append(blackmail.To("Name", "victim@example.com"), blackmail.Cc("Other", "other@example.com")...),
    blackmail.Text("Text part")
    blackmail.HTML("HTML part",
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

Supports signing out-of-the-box (**this is not yet functional**):

```go
// Create a new signing key.
priv, pub, err := blackmail.SignCreateKeys()

// Convenience function to read keys from filesystem.
//priv, pub, err := blackmail.SignKeys("test.priv", "test.pub")

err := blackmail.Send("Subject!",
    blackmail.Address("My name", "myemail@example.com"),
    blackmail.To("Name", "addr"),
    blackmail.Bodyf("Well, hello there!"),
    blackmail.Sign(priv, pub)
```

Note there is no support for PGP encryption (and never will be).

You can use the `blackmail_no_sign` build tag to exclude signing support and
avoid depending on golang.org/x/crypto if you want.


Questions you may have 
----------------------

### Is this package stable?

Not quite; I might tweak the API a bit in the future. In particular, right now
it panics() on most errors in `Message()`. This is mostly okay since those kind
of errors *Should Never Happen™*, but it would be nicer if they're propagated
back up and Message() returns an error.

I'm also not 100% satisfied with how passing options to the `Mailer` works, and
this *may* get a backwards incompatible change.

I'll probably also change some of the smtp package.

### Regular users will never understand all this OpenPGP signing stuff!

Setting up email clients to *verify* signatures is easy:

1. Import public key from a trusted(ish) source, such as the applications
   website or "welcome to our service" email.

And that's it. Signing your *own* stuff, encryption, and key distribution from
random strangers from the internet is hard, but this kind of trust-on-first-use
model isn't too hard.

I suspect a lot of the opposition against *any* form of PGP comes from people
traumatised from the `gpg` CLI or other really hard PGP interfaces like
Enigmail. If you restrict yourself to just a subset then it's mostly okay.

I wrote a thing about this last year: [Why isn’t Amazon.com signing their
emails?][sign].

### But that gives a false sense of security!

There's always at least one person who says that, and I don't buy it. Does a
cheap lock on your front door give you a "false sense of security" or does it
make it harder for many people to break in to your house?

Even experts can struggle to determine if an email is genuine or a phising/scam
attempt. Signing doesn't provide perfect protection against it, but it does
improve on the current situation – a situation which has been unchanged for over
20 years. Perfect security guarantees don't exist, but this is *better*
security.

There are perhaps better solutions – there is certainly space for a better
signing protocol like minisign – but the infrastructure and support already
exists for OpenPGP and it will be years before *[something-else]* will gain
enough traction to be usable. For the time being, OpenPGP is what we're stuck
with.

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


