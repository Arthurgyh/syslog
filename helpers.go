// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import (
	"io"
	"strings"
	"time"
)

// Optional allow a part of the message to optional, it checks if the next read
// returns a io.EOF err and if so return nil as error. It only checks for EOF
// once. So if multiple functions are passed the second part is required if the
// first part is present.
func optional(peekLength int, fns ...parseFunc) parseFunc {
	return func(buf *buffer, msg *Message) error {
		if _, err := buf.Peek(peekLength); err == io.EOF {
			return nil
		}

		for _, fn := range fns {
			if err := fn(buf, msg); err != nil {
				return err
			}
		}
		return nil
	}
}

// Requires Priority to be set on the Message.
func calculateFacility(buf *buffer, msg *Message) error {
	msg.Facility = msg.Priority.CalculateFacility()
	return nil
}

// Requires Priority to be set on the Message.
func calculateSeverity(buf *buffer, msg *Message) error {
	msg.Severity = msg.Priority.CalculateSeverity()
	return nil
}

// Requires Timestamp to be set on the Message.
// This adds the years to the timestamp.
func nginxFixTimestamp(buf *buffer, msg *Message) error {
	msg.Timestamp = msg.Timestamp.AddDate(time.Now().Year(), 0, 0)
	return nil
}

// Requires Appname to be set on the Message.
// The format Nginx uses adds a colon to seperate the appname from the message
// (or structered data), we trim that colon using this function.
func nginxFixAppName(buf *buffer, msg *Message) error {
	msg.Appname = strings.TrimSuffix(msg.Appname, ":")
	return nil
}
