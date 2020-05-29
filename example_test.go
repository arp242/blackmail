package blackmail_test

// func ExampleBasic() {
// 	blackmail.DefaultMailer = blackmail.NewMailer(blackmail.ConnectWriter, blackmail.MailerOut(os.Stdout))
//
// 	err := blackmail.Send("Send me bitcoins or I will leak your browsing history!",
// 		blackmail.From("", "blackmail@example.com"),
// 		blackmail.To("Name", "victim@example.com"),
// 		blackmail.Bodyf("I can haz ur bitcoinz?"))
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	// Output: asd
// }
//
// func ExampleAttachment() {
// 	blackmail.DefaultMailer = blackmail.NewMailer(blackmail.ConnectWriter, blackmail.MailerOut(os.Stdout))
//
// 	err := blackmail.Send("I saw what you did last night 😏",
// 		blackmail.From("😏", "blackmail@example.com"),
// 		append(blackmail.To("Name", "victim@example.com"), blackmail.Cc("Other", "other@example.com")...),
// 		blackmail.BodyText("Text part"),
// 		blackmail.BodyHTML(`HTML part: <img src="cid:blackmail:1">`,
// 			blackmail.InlineImage("image/png", "logo.png", []byte{0x00, 0x01, 0x02})))
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	// Output: asd
// }
//
// func ExampleMailer() {
// 	// You can create your own (re-usable) mailer.
// 	// mailer := blackmail.NewMailer("smtp://user:pass@localhost:25")
// 	// err := mailer.Send()
//
// 	// // Add some options to your mailer.
// 	// mailer = blackmail.NewMailer("smtp://user:pass@localhost:25",
// 	// 	blackmail.MailerAuth(),
// 	// 	blackmail.MailerTLS(&tls.Config{}),
// 	// 	blackmail.RequireSTARTLS(true))
//
// 	// // Get RF5322 message with a list of recipients to send it to (To + Cc + Bcc).
// 	// msg, to, err := blackmail.Message()
//
// 	// Output: asd
// }
