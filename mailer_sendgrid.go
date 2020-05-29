package blackmail

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"

	"zgo.at/blackmail/sg"
)

type mailerSendGrid struct {
	apiKey  string
	sandbox bool
	httpC   *http.Client
	mod     func(*sg.Message)
}

func createSGMessage(subject string, from mail.Address, parts ...Part) sg.Message {
	body, rcpt, headers := splitParts(parts)
	_, _ = rcpt, headers

	msg := sg.Message{
		Subject: subject,
		From:    sg.Address{Name: from.Name, Email: from.Address},
	}
	var p sg.Personalization
	// for _, r := range rcpt {
	// 	switch r.kind {
	// 	case rcptTo:
	// 		p.To = append(p.To, sg.Address{Name: r.Address.Name, Email: r.Address.Address})
	// 	case rcptCc:
	// 		p.Cc = append(p.Cc, sg.Address{Name: r.Address.Name, Email: r.Address.Address})
	// 	case rcptBcc:
	// 		p.Bcc = append(p.Bcc, sg.Address{Name: r.Address.Name, Email: r.Address.Address})
	// 	}
	// }
	msg.Personalizations = []sg.Personalization{p}

	for _, p := range body {
		switch {
		// TODO: not quite correct.
		case p.attach || p.inlineAttach:
			msg.Attachments = append(msg.Attachments, sg.Attachment{
				Content:     base64.StdEncoding.EncodeToString(p.body),
				Type:        p.ct,
				Filename:    p.filename,
				Disposition: map[bool]string{true: "inline", false: "attachment"}[p.inlineAttach],
				ContentID:   p.cid,
			})
		// case len(p.headers) > 0:
		// 	msg.Headers = make(map[string]string, len(p.headers)/2)
		// 	for i := range p.headers {
		// 		if i%2 == 0 {
		// 			msg.Headers[p.headers[i]] = p.headers[i+1]
		// 		}
		// 	}
		default:
			msg.Content = append(msg.Content, sg.Content{
				Type:  p.ct,
				Value: string(p.body),
			})
		}
	}

	return msg
}

func (m mailerSendGrid) Send(subject string, from mail.Address, parts ...Part) error {
	msg := createSGMessage(subject, from, parts...)
	if m.sandbox {
		msg.SandboxMode = &sg.Enable{Enable: true}
	}
	if m.mod != nil {
		m.mod(&msg)
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("blackmail.mailerSendGrid: %w", err)
	}

	r, err := http.NewRequest(http.MethodPost, "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("blackmail.mailerSendGrid: %w", err)
	}

	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+m.apiKey)
	resp, err := m.httpC.Do(r)
	if err != nil {
		return fmt.Errorf("blackmail.mailerSendGrid: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 { // No error: our work here is done.
		io.Copy(io.Discard, resp.Body)
		return nil
	}

	sgErr := sg.Error{Status: resp.Status, StatusCode: resp.StatusCode}
	respBody, err := io.ReadAll(resp.Body)
	if err == nil { // Failure reading the error is non-fatal.
		_ = json.Unmarshal(respBody, &sgErr)
	}
	return sgErr
}
