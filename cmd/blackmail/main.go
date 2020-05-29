package main

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"zgo.at/blackmail"
	"zgo.at/blackmail/smtp"
	"zgo.at/zli"
)

const usage = `Send an email with the blackmail library.

Required flags:

    -m, -mailer    blackmail Mailer to use; allowed values:

                       stdout (default)
                       direct
                       sendgrid     sendgrid://api_key sandbox=true
                       relay URL    smtp://...

    -s, -subject   Subject: header.

    -to            Set recipient(s), as a plain email address. Can be added more
    -cc            Than once. At least one of these must be present.
    -bcc

Optional flags:

    -f, -from      From: header; set to <user>@<hostname> by default.

    -H, -header    Additional headers, as "key=value". Can be added more than once.

    -d, -debug     Show SMTP interactions.

Exit codes:

    1          Error constructing the message.
    2          Error sending the message.
`

// TODO: allow setting names -from, -to, etc.
//
// TODO: allow constructing more advanced message bodies:
//   blackmail -body text:foo.txt,html:foo.html,image.png,attach:other.png
func main() {
	f := zli.NewFlags(os.Args)
	var (
		help    = f.Bool(false, "h", "help")
		mailer  = f.String("stdout", "m", "mailer")
		from    = f.String("", "f", "from")
		subject = f.String("", "s", "subject")
		to      = f.StringList(nil, "to")
		cc      = f.StringList(nil, "cc")
		bcc     = f.StringList(nil, "bcc")
		debug   = f.Bool(false, "d", "debug")
		headers = f.StringList(nil, "H", "headers")
	)
	zli.F(f.Parse())

	if help.Bool() {
		fmt.Println(usage)
		return
	}

	if !to.Set() && !cc.Set() && !bcc.Set() {
		zli.Fatalf("at least one of -to, -cc, or -bcc is required")
	}

	if from.String() == "" {
		u, err := user.Current()
		if err != nil {
			zli.Fatalf("get user for -from: %s", err)
		}
		h, err := os.Hostname()
		if err != nil {
			zli.Fatalf("get hostname for -from: %s", err)
		}
		if hh := strings.Split(h, "."); len(hh) > 2 {
			h = hh[len(hh)-2] + "." + hh[len(hh)-1]
		}
		*from.Pointer() = u.Username + "@" + h
	}

	fp, err := zli.InputOrFile(f.Shift(), false)
	zli.F(err)
	defer fp.Close()

	body, err := io.ReadAll(fp)
	zli.F(err)
	fp.Close()

	var m blackmail.Mailer
	mm := mailer.String()
	switch {
	case mm == "stdout":
		m = blackmail.NewMailerWriter(os.Stdout)
	case mm == "direct":
		m = blackmail.NewMailerSMTP()
	case strings.HasPrefix(mm, "smtp://"):
		m = blackmail.NewMailerSMTP(blackmail.MailerRelay(mm))
	case strings.HasPrefix(mm, "sendgrid://"):
		m = blackmail.NewMailerSendGrid(mm[11:], blackmail.MailerSandbox(true))
	default:
		zli.Fatalf("unknown mailer: %s", mailer)
	}

	parts := blackmail.Parts{blackmail.BodyText(string(body))}
	if headers.Set() {
		parts = append(parts, blackmail.HeaderPart{}.FromKV(':', headers.Strings()...))
	}

	smtp.Debug = debug.Bool()

	err = m.Send(subject.String(),
		blackmail.From("", from.String()),
		//blackmail.Rcpt(
		//	blackmail.ToList(to.Strings()...),
		//	blackmail.CcList(cc.Strings()...),
		//	blackmail.BccList(bcc.Strings()...)),
		parts...)
	if err != nil {
		zli.Errorf("%s", err)
		os.Exit(2)
	}
}
