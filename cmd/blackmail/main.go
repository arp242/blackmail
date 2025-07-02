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

    -smtp            Relay URL ("smtp://user:pass@host:25") or "stdout"

    -debug           Print full transaction to stdout.

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
		from, to      string
		debug         bool
	)
	flag.StringVar(&smtp, "smtp", "stdout", "")
	flag.StringVar(&from, "from", "", "")
	flag.StringVar(&subject, "subject", "", "")
	flag.StringVar(&to, "to", "", "")
	flag.BoolVar(&debug, "debug", false, "")
	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(os.Args) == 1 {
		fmt.Print(usage)
		return
	}

	if from == "" {
		fmt.Fprintln(os.Stderr, "-from needs to be set")
		os.Exit(1)
	}
	if to == "" {
		fmt.Fprintln(os.Stderr, "-to needs to be set")
		os.Exit(1)
	}

	rcpt := blackmail.To(to)
	parts := blackmail.Bodyf("Test\r\n")

	m := blackmail.NewWriter(os.Stdout)
	if smtp != "stdout" {
		opt := blackmail.RelayOptions{}
		if debug {
			opt.Debug = os.Stdout
		}
		m, err = blackmail.NewRelay(smtp, &opt)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = m.Send(subject, mail.Address{Address: from}, rcpt, parts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}
