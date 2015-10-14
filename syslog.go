// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

// todo: doc package.
package syslog

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"time"
)

// todo: only allow PRINTUSASCII, currently not checked: %d33-126.
// todo: create format error to give information on where the error is located
// (index)?

// Message represents a single message.
type Message struct {
	Priority  Priority
	Facility  Facility
	Severity  Severity
	Version   uint
	Timestamp time.Time
	Hostname  string
	Appname   string
	ProcessID string
	MessageID string
	Data      map[string]map[string]string
	Message   string
}

func ParseMessage(b []byte, format format) (*Message, error) {
	br := bufio.NewReader(bytes.NewBuffer(b))

	var msg Message
	for _, parseFunc := range format {
		if err := parseFunc(br, &msg); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}

	return &msg, nil
}

func newFormatError(msg string) error {
	return errors.New("syslog: format incorrect: " + msg)
}
