package smtp

import (
	"errors"
	"io"
	"time"
)

type (
	// DataCommand is a pending DATA command. DataCommand is an io.WriteCloser.
	// See Client.Data.
	DataCommand struct {
		client *Client
		wc     io.WriteCloser

		closeErr error
	}

	// DataResponse is the response returned by a DATA command. See
	// DataCommand.CloseWithResponse.
	DataResponse struct {
		// StatusText is the status text returned by the server. It may contain
		// tracking information.
		StatusText string
	}
)

var _ io.WriteCloser = (*DataCommand)(nil)

// Write implements io.Writer.
func (cmd *DataCommand) Write(b []byte) (int, error) {
	return cmd.wc.Write(b)
}

// Close implements io.Closer.
func (cmd *DataCommand) Close() error {
	_, err := cmd.CloseWithResponse()
	return err
}

// CloseWithResponse is equivalent to Close, but also returns the server
// response.
//
// If server returns an error, it will be of type *SMTPError.
func (cmd *DataCommand) CloseWithResponse() (*DataResponse, error) {
	if err := cmd.close(); err != nil {
		return nil, err
	}

	cmd.client.conn.SetDeadline(time.Now().Add(cmd.client.SubmissionTimeout))
	defer cmd.client.conn.SetDeadline(time.Time{})

	_, msg, err := cmd.client.readResponse(250)
	if err != nil {
		cmd.closeErr = err
		return nil, err
	}

	return &DataResponse{StatusText: msg}, nil
}

func (cmd *DataCommand) close() error {
	if cmd.closeErr != nil {
		return cmd.closeErr
	}

	if err := cmd.wc.Close(); err != nil {
		cmd.closeErr = err
		return err
	}

	cmd.closeErr = errors.New("smtp: data writer closed twice")
	return nil
}
