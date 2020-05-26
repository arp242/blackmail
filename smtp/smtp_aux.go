package smtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
)

var testHookStartTLS func(*tls.Config) // nil, except for tests

type dataCloser struct {
	c *Client
	io.WriteCloser
	statusCb func(rcpt string, status *SMTPError)
}

func (d *dataCloser) Close() error {
	d.WriteCloser.Close()
	expectedResponses := len(d.c.rcpts)
	if d.c.lmtp {
		for expectedResponses > 0 {
			rcpt := d.c.rcpts[len(d.c.rcpts)-expectedResponses]
			if _, _, err := d.c.Text.ReadResponse(250); err != nil {
				if protoErr, ok := err.(*textproto.Error); ok {
					if d.statusCb != nil {
						d.statusCb(rcpt, toSMTPErr(protoErr))
					}
				} else {
					return err
				}
			} else if d.statusCb != nil {
				d.statusCb(rcpt, nil)
			}
			expectedResponses--
		}
		return nil
	} else {
		_, _, err := d.c.Text.ReadResponse(250)
		if err != nil {
			if protoErr, ok := err.(*textproto.Error); ok {
				return toSMTPErr(protoErr)
			}
			return err
		}
		return nil
	}
}

func parseEnhancedCode(s string) (EnhancedCode, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return EnhancedCode{}, fmt.Errorf("wrong amount of enhanced code parts")
	}

	code := EnhancedCode{}
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return code, err
		}
		code[i] = num
	}
	return code, nil
}

// toSMTPErr converts textproto.Error into SMTPError, parsing
// enhanced status code if it is present.
func toSMTPErr(protoErr *textproto.Error) *SMTPError {
	if protoErr == nil {
		return nil
	}
	smtpErr := &SMTPError{
		Code:    protoErr.Code,
		Message: protoErr.Msg,
	}

	parts := strings.SplitN(protoErr.Msg, " ", 2)
	if len(parts) != 2 {
		return smtpErr
	}

	enchCode, err := parseEnhancedCode(parts[0])
	if err != nil {
		return smtpErr
	}

	smtpErr.EnhancedCode = enchCode
	smtpErr.Message = parts[1]
	return smtpErr
}

// validateLine checks to see if a line has CR or LF as per RFC 5321.
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}

func encodeXtext(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))

	for _, ch := range raw {
		if ch == '+' || ch == '=' {
			out.WriteRune('+')
			out.WriteString(strings.ToUpper(strconv.FormatInt(int64(ch), 16)))
		}
		if ch > '!' && ch < '~' { // printable non-space US-ASCII
			out.WriteRune(ch)
		}
		// Non-ASCII.
		out.WriteRune('+')
		out.WriteString(strings.ToUpper(strconv.FormatInt(int64(ch), 16)))
	}
	return out.String()
}
