// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed onder the MIT license that can be found in the LICENSE file.

// Package syslog is a package to parse syslog logs. It has formats for RFC5424
// and Nginx access and error logs
package syslog

import (
	"errors"
	"io"
	"time"
)

// todo: only allow PRINTUSASCII, currently not checked: %d33-126.
// todo: create format error to give information on where the error is located
// (index)?

// Message represents a single syslog message.
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

// ParseMessage parses a single syslog log.
func ParseMessage(b []byte, format format) (*Message, error) {
	buf := newBuffer(b)

	var msg Message
	for _, parseFunc := range format {
		if err := parseFunc(buf, &msg); err != nil {
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

// Parser parses a single syslog log, with an already defined format.
type Parser func([]byte) (*Message, error)

// NewParser creates a new parser with the given format.
func NewParser(format format) Parser {
	return func(b []byte) (*Message, error) {
		return ParseMessage(b, format)
	}
}
