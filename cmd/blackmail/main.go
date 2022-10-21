package main

import (
	"flag"
	"fmt"
	"net/mail"
	"os"

	"zgo.at/blackmail"
)

const usage = `Send an email with the blackmail library.

Required flags:

    -mailer          stdout, direct, or a relay URL ("smtp://user:pass@host:25")

    -subject         Subject: header.

    -to, -cc, -bcc   Set recipient(s), as a plain email address.
                     Add multiple times to send to multiple people.
                     At least one of these must be present.

Optional flags:

    -from      From: header; set to <user>@<hostname> by default.

    -body      Read message body from a file. The default is to read from stdin.
`

func main() {
	flag.Usage = func() { fmt.Print(usage) }

	var (
		smtp, subject string
		from          string
		to            string
	)
	flag.StringVar(&smtp, "smtp", blackmail.ConnectWriter, "")
	flag.StringVar(&from, "from", "", "")
	flag.StringVar(&subject, "subject", "", "")
	flag.StringVar(&to, "to", "", "")
	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if from == "" || to == "" {
		fmt.Fprintln(os.Stderr, "Need more args")
		os.Exit(1)
	}

	rcpt := blackmail.To(to)
	parts := blackmail.Bodyf("Test\r\n")

	m := blackmail.NewMailer(smtp)
	err = m.Send(subject, mail.Address{Address: from}, rcpt, parts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}
