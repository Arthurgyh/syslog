// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

package syslog

import (
	"bufio"
	"io"
	"strings"
	"time"
)

// Optional allow a part of the message to optional, it checks if the next read
// returns a io.EOF err and if so return nil as error. It only checks for EOF
// once. So if multiple functions are passed the second part is required if the
// first part is present.
func optional(peekLength int, fns ...parseFunc) parseFunc {
	return func(b *bufio.Reader, msg *Message) error {
		if _, err := b.Peek(peekLength); err == io.EOF {
			return nil
		}

		for _, fn := range fns {
			if err := fn(b, msg); err != nil {
				return err
			}
		}
		return nil
	}
}

// Requires Priority to be set on the Message.
func calculateFacility(b *bufio.Reader, msg *Message) error {
	msg.Facility = msg.Priority.CalculateFacility()
	return nil
}

// Requires Priority to be set on the Message.
func calculateSeverity(b *bufio.Reader, msg *Message) error {
	msg.Severity = msg.Priority.CalculateSeverity()
	return nil
}

// Requires Timestamp to be set on the Message.
// This adds the years and location to the timestamp.
func nginxFixTimestamp(b *bufio.Reader, msg *Message) error {
	now := time.Now()
	msg.Timestamp = time.Date(now.Year(), msg.Timestamp.Month(),
		msg.Timestamp.Day(), msg.Timestamp.Hour(), msg.Timestamp.Minute(),
		msg.Timestamp.Second(), 0, now.Location())
	return nil
}

// Requires Appname to be set on the Message.
// The format Nginx uses adds a colon to seperate the appname from the message
// (or structered data), we trim that colon using this function.
func nginxFixAppName(b *bufio.Reader, msg *Message) error {
	msg.Appname = strings.TrimSuffix(msg.Appname, ":")
	return nil
}
