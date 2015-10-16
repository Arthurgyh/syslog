// Copyright (C) 2015 Thomas de Zeeuw.
//
// Licensed under the MIT license that can be found in the LICENSE file.

// Package syslog is a package to parse syslog logs. It has formats for RFC5424
// and Nginx access and error logs
package syslog

import (
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
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

// String formats the message in a RFC5424 format.
func (msg *Message) String() string {
	return string(msg.Bytes())
}

// Bytes formats the message in a RFC5424 format.
func (msg *Message) Bytes() []byte {
	var b []byte

	// Format priority: <pri>, e.g. <0>, <191>
	b = append(b, priorityStart)
	b = strconv.AppendUint(b, uint64(msg.Priority), 10)
	b = append(b, priorityEnd)

	// Add optional version and a space, e.g. 1, 10
	if msg.Version != 0 {
		b = strconv.AppendUint(b, uint64(msg.Version), 10)
	}
	b = append(b, spaceByte)

	// Add values, with a nil value for a zero value.
	b = addTimestamp(b, msg.Timestamp)
	b = addValue(b, msg.Hostname)
	b = addValue(b, msg.Appname)
	b = addValue(b, msg.ProcessID)
	b = addValue(b, msg.MessageID)

	b = addData(b, msg.Data)

	if msg.Message != "" {
		b = append(b, spaceByte)
		b = append(b, msg.Message...)
	}

	return b
}

func addTimestamp(b []byte, t time.Time) []byte {
	if t.IsZero() {
		b = append(b, nilValueByte)
	} else {
		b = t.AppendFormat(b, time.RFC3339Nano)
	}
	b = append(b, spaceByte)
	return b
}

// addValue adds a value and a space to the given bytes. If the value is empty
// a nil value (RFC5424) is added.
func addValue(b []byte, value string) []byte {
	if value == "" {
		b = append(b, nilValueByte)
	} else {
		b = append(b, strings.TrimSpace(value)...)
	}
	b = append(b, spaceByte)
	return b
}

// Add data in the following format:
// [dataId name="value" name2="value2"][dataId2 name="value"].
func addData(b []byte, data map[string]map[string]string) []byte {
	if len(data) == 0 {
		b = append(b, nilValueByte)
		return b
	}

	for _, dataID := range getSortedMapMapKeys(data) {
		params := data[dataID]

		b = append(b, dataStart)
		b = append(b, dataID...)

		// Add name and value in the following format: ` name="value"`
		for _, name := range getSortedMapKeys(params) {
			value := params[name]
			b = append(b, spaceByte)
			b = append(b, name...)
			b = append(b, equalByte)
			b = strconv.AppendQuote(b, value)
		}

		b = append(b, dataEnd)
	}

	return b
}

func getSortedMapKeys(m map[string]string) []string {
	var keys = make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func getSortedMapMapKeys(m map[string]map[string]string) []string {
	var keys = make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
